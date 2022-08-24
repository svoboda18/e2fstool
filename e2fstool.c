#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <getopt.h>
#include <string.h>

#include "e2fstool.h"

const char * prog_name = "e2fstool";
char *in_file;
char *out_dir;
char *conf_dir;
__u8 *mountpoint = NULL;
int android_configure;
int android_sparse_file = 1;

void usage(int ret)
{
    fprintf(stderr, "%s [-c config_dir] [-m mountpoint]\n"
            "\t img_file out_dir\n",
            prog_name);
    exit(ret);
}

errcode_t ino_get_xattr(ext2_filsys fs, ext2_ino_t ino, const char *key, void **val, size_t *val_len)
{
    errcode_t retval, close_retval;
    struct ext2_xattr_handle *xhandle;

    retval = ext2fs_xattrs_open(fs, ino, &xhandle);
    if (retval) {
        com_err(__func__, retval, "while opening inode %u", ino);
        return retval;
    }

    retval = ext2fs_xattrs_read(xhandle);
    if (retval) {
        com_err(__func__, retval,
            "while reading xattrs of inode %u", ino);
        goto xattrs_close;
    }

    retval = ext2fs_xattr_get(xhandle, key, val, val_len);
    if (retval && retval != EXT2_ET_EA_KEY_NOT_FOUND) {
        com_err(__func__, retval,
            "while reading xattrs of inode %u", ino);
        goto xattrs_close;
    }

xattrs_close:
    close_retval = ext2fs_xattrs_close(&xhandle);
    if (close_retval) {
        com_err(__func__, close_retval,
            "while closing xattrs of inode %u", ino);
    }
    return retval;
}

errcode_t ino_get_selinux_xattr(ext2_filsys fs, ext2_ino_t ino,
               void **val, size_t *val_len)
{
    errcode_t retval;

    retval = ino_get_xattr(fs, ino, "security." XATTR_SELINUX_SUFFIX, val, val_len);

    if (retval == EXT2_ET_EA_KEY_NOT_FOUND)
        return 0;
    else
        return retval;
}

errcode_t ino_get_capabilities_xattr(ext2_filsys fs, ext2_ino_t ino,
               uint64_t *val)
{
    errcode_t retval;
    struct vfs_cap_data *cap_data;
    size_t len;
    uint64_t cap = 0;

    retval = ino_get_xattr(fs, ino, "security." XATTR_CAPS_SUFFIX, (void **)&cap_data, &len);
    if (retval) {
        goto end;
    }

    if (cap_data->magic_etc & VFS_CAP_REVISION) {
        cap = ((uint64_t)(cap_data->data[1].permitted) << 32 | (uint64_t)cap_data->data[0].permitted);
    } else {
        fprintf(stderr, "%s: Unknown capabilities revision 0x%x\n", __func__, cap_data->magic_etc & VFS_CAP_REVISION_MASK);
    }

end:
    *val = cap;

    if (retval == EXT2_ET_EA_KEY_NOT_FOUND)
        return 0;
    else
        return retval;
}

errcode_t ino_get_config(ext2_ino_t ino, struct ext2_inode inode, char *path, void *priv_data)
{
    char *ctx = NULL;
    FILE *contexts, *filesystem;
    size_t ctx_len;
    uint64_t cap;
    struct inode_params *params = (struct inode_params *)priv_data;
    unsigned char is_root = (path == (char *)params->mountpoint);
    errcode_t retval = 0;

    contexts = fopen(params->se_path, "a");
    if (!contexts) {
        params->error = errno;
        return -1;
    }

    filesystem = fopen(params->fs_path, "a");
    if (!filesystem) {
        params->error = errno;
        retval = -1;
        goto err;
    }

    retval = ino_get_selinux_xattr(params->fs, ino, (void **)&ctx, &ctx_len);
    if (retval) {
        return retval;
    }

    retval = ino_get_capabilities_xattr(params->fs, ino, &cap);
    if (retval) {
        return retval;
    }

    if (is_root) {
        retval = fprintf(filesystem, "/ %u %u %o capabilities=%lu\n", inode.i_uid, inode.i_gid, inode.i_mode & FILE_MODE_MASK, cap);
    } else {
        retval = fprintf(filesystem, "%s %u %u %o capabilities=%lu\n", path, inode.i_uid, inode.i_gid, inode.i_mode & FILE_MODE_MASK, cap);
    }
    if (retval < 0) {
        params->error = errno;
        return  -1;
    }

    if (ctx) {
        if (is_root) {
            if (*path == '\0') {
                retval = fprintf(contexts, "(/.*)? %.*s\n", ctx_len, ctx);
            } else {
                retval = fprintf(contexts, "/%s(/.*)? %.*s\n", path, ctx_len, ctx);
            }
        } else {
            retval = fprintf(contexts, "/%s %.*s\n", path, ctx_len, ctx);
        }
    }
    if (retval < 0) {
        params->error = errno;
        return -1;
    }

    fclose(filesystem);
err:
    fclose(contexts);
    return retval == -1 ? -1 : 0;
}

errcode_t ino_extract_symlink(ext2_filsys fs, ext2_ino_t ino, struct ext2_inode *inode,
              const char *path)
{
    ext2_file_t e2_file;
    char *link_target = NULL;
    __u32 i_size = inode->i_size;
    errcode_t retval = 0;

    link_target = malloc(i_size + 1);
    if (!link_target) {
        com_err(__func__, errno, "while allocating memory");
        return EXT2_ET_NO_MEMORY;
    }

    if (i_size < SYMLINK_I_BLOCK_MAX_SIZE) {
        strncpy(link_target, (char *) inode->i_block, i_size + 1);
    } else {
        unsigned bytes = i_size;
        char *p = link_target;
        retval = ext2fs_file_open(fs, ino, 0, &e2_file);
        if (retval) {
            com_err(__func__, retval, "while opening ex2fs symlink");
            goto end;
        }
        for (;;) {
            unsigned int got;
            retval = ext2fs_file_read(e2_file, p, bytes, &got);
            if (retval) {
                com_err(__func__, retval, "while reading ex2fs symlink");
                goto end;
            }
            bytes -= got;
            p += got;
            if (got == 0 || bytes == 0)
                break;
        }
        link_target[i_size] = '\0';
        retval = ext2fs_file_close(e2_file);
        if (retval) {
            com_err(__func__, retval, "while closing symlink");
            goto end;
        }
    }

    retval = symlink(link_target, path);
    if (retval == -1) {
        fprintf(stderr, "%s: %s while creating symlink %s", __func__, strerror(errno), path);
        retval = errno;
    }

end:
    free(link_target);
    return retval;
}

errcode_t ino_extract_regfile(ext2_filsys fs, ext2_ino_t ino, const char *path)
{
    ext2_file_t e2_file;
    struct ext2_inode inode;
    char *buf = NULL;
    int fd, nbytes;
    unsigned int written = 0, got;
    errcode_t retval = 0, close_retval = 0;

    retval = ext2fs_read_inode(fs, ino, &inode);
    if (retval) {
        com_err(__func__, retval, "while reading file inode %u", ino);
        return retval;
    }

    fd = open(path, O_WRONLY | O_TRUNC | O_BINARY | O_CREAT, 0644);
    if (fd < 0) {
        com_err(__func__, errno, "while creating file");
        return errno;
    }

    retval = ext2fs_file_open(fs, ino, 0, &e2_file);
    if (retval) {
        com_err(__func__, retval, "while opening ext2 file");
        goto end;
    }

    retval = ext2fs_get_mem(FILE_READ_BUFLEN, &buf);
    if (retval) {
        com_err(__func__, retval, "while allocating memory");
        goto end;
    }

    while (1) {
        retval = ext2fs_file_read(e2_file, buf, FILE_READ_BUFLEN, &got);
        if (retval) {
            com_err(__func__, retval, "while reading ext2 file");
            goto quit;
        }

        if (got == 0)
            break;

        while (got) {
            nbytes = write(fd, buf, got);
            if (nbytes < 0) {
                if (errno == EINTR) {
                    continue;
                }
                com_err(__func__, errno, "while writing file");
                goto close;
            }

            got -= nbytes;
            written += nbytes;
        }
    }

    if (inode.i_size != written) {
        errno = EFAULT;
        com_err(__func__, errno, "while writing file (%u of %u)", written, inode.i_size);
    }

close:
    close_retval = ext2fs_file_close(e2_file);
    if (close_retval)
        com_err(__func__, close_retval, "while closing ext2 file\n");
quit:
    ext2fs_free_mem(&buf);
end:
    close(fd);
    retval |= close_retval;
    return retval;
}

int walk_dir(ext2_ino_t dir,
            int flags EXT2FS_ATTR((unused)),
            struct ext2_dir_entry *de,
            int offset EXT2FS_ATTR((unused)),
            int blocksize EXT2FS_ATTR((unused)),
            char *buf EXT2FS_ATTR((unused)), void *priv_data)
{
    __u16 name_len, filename_len;
    char *output_file;
    struct ext2_inode inode;
    struct inode_params *params = (struct inode_params *)priv_data;
    errcode_t retval = 0;

    name_len = de->name_len & 0xff;
    if (!strncmp(de->name, ".", name_len) || (!strncmp(de->name, "..", name_len)))
        return 0;

    filename_len = asprintf(&params->filename, "%s/%.*s", params->path,
                   name_len, de->name);
    if (filename_len < 0) {
        params->error = EXT2_ET_NO_MEMORY;
        return -1;
    }

    if (asprintf(&output_file, "%s%.*s", out_dir, filename_len,
                 params->filename) < 0) {
        params->error = EXT2_ET_NO_MEMORY;
        retval = -1;
        goto end;
    }

    retval = ext2fs_read_inode(params->fs, de->inode, &inode);
    if (retval) {
        com_err(__func__, retval, "while reading inode %u", de->inode);
        goto err;
    }

    if (android_configure) {
        char *config_path = NULL;

        retval = (*params->mountpoint == '\0')
              ? asprintf(&config_path, "%.*s", filename_len - 1, params->filename + 1)
              : asprintf(&config_path, "%s%.*s", params->mountpoint, filename_len, params->filename);
        if (retval < 0) {
            params->error = EXT2_ET_NO_MEMORY;
            goto err;
        }

        retval = ino_get_config(de->inode, inode, config_path, params);
        free(config_path);

        if (retval) {
#define ERROR_MESSAGE "while getting config for inode %u"
            retval != -1 ? com_err(__func__, retval, ERROR_MESSAGE, de->inode)
                         : fprintf(stderr, "%s: %s" ERROR_MESSAGE, __func__, strerror(params->error), de->inode);
            goto err;
#undef ERROR_MESSAGE
        }
    }

    if (dir == EXT2_ROOT_INO &&
        !strncmp(de->name, "lost+found", name_len)) goto err;

    fprintf(stdout, "Extracting %s\n", params->filename + 1);

    switch(inode.i_mode & LINUX_S_IFMT) {
        case LINUX_S_IFCHR:
        case LINUX_S_IFBLK:
        case LINUX_S_IFIFO:
#if !defined(_WIN32) || defined(SVB_WIN32)
#if defined(S_IFSOCK) && !defined(SVB_WIN32)
        case LINUX_S_IFSOCK:
#endif
        case LINUX_S_IFLNK:
            retval = ino_extract_symlink(params->fs, de->inode, &inode, output_file);
            if (retval) {
                goto err;
            }
            break;
#endif
        case LINUX_S_IFREG:
            retval = ino_extract_regfile(params->fs, de->inode, output_file);
            if (retval) {
                goto err;
            }
            break;
        case LINUX_S_IFDIR: ;
            char *cur_path = params->path;
            char *cur_filename = params->filename;
            params->path = params->filename;

            retval = mkdir(output_file, inode.i_mode & FILE_MODE_MASK);
            if (retval == -1 && errno != EEXIST) {
                fprintf(stderr, "%s: %s while creating %s\n", __func__, strerror(errno), output_file);
                goto err;
            }

            retval = ext2fs_dir_iterate2(params->fs, de->inode, 0, NULL,
                             walk_dir, params);
            if (retval) {
                goto err;
            }
            params->path = cur_path;
            params->filename = cur_filename;
            break;
        default:
            fprintf(stderr, "%s: warning: unknown entry \"%s\" (%x)", __func__, params->filename, inode.i_mode & LINUX_S_IFMT);
    }

err:
    free(output_file);
end:
    free(params->filename);
    return retval ? -1 : 0;
}

errcode_t walk_fs(ext2_filsys fs)
{
    struct ext2_inode inode;
    struct inode_params params = {
        .fs = fs,
        .path = "",
        .filename = "",
        .mountpoint = NULL,
        .fs_path = NULL,
        .se_path = NULL,
        .error = 0
    };
    errcode_t retval = 0;

    retval = ext2fs_read_inode(fs, EXT2_ROOT_INO, &inode);
    if (retval) {
        com_err(__func__, retval, "while reading root inode");
        return retval;
    }

    retval = mkdir(out_dir, S_IRWXU | S_IRWXG | S_IRWXO);
    if (retval == -1 && errno != EEXIST) {
        fprintf(stderr, "%s: %s while creating %s\n", __func__, strerror(errno), out_dir);
        return errno;
    }

    if (android_configure) {
        if (mountpoint)
            params.mountpoint = mountpoint;
        else if (*fs->super->s_last_mounted != '\0')
            params.mountpoint = fs->super->s_last_mounted;
        else if (*fs->super->s_volume_name != '\0')
            params.mountpoint = fs->super->s_volume_name;
        else
            params.mountpoint = (__u8 *)out_dir;

        if (*params.mountpoint == '/') ++params.mountpoint;

        retval = mkdir(conf_dir, S_IRWXU | S_IRWXG | S_IRWXO);
        if (retval == -1 && errno != EEXIST) {
            fprintf(stderr, "%s while creating %s\n", strerror(errno), conf_dir);
            return errno;
        }

        if (asprintf(&params.fs_path, "%s/filesystem_config.fs", conf_dir) < 0 ||
            asprintf(&params.se_path, "%s/selinux_contexts.fs", conf_dir) < 0) {
            com_err(__func__, EXT2_ET_NO_MEMORY, "while configuring config paths");
            return 1;
        }
        retval = ino_get_config(EXT2_ROOT_INO, inode, (char *)params.mountpoint, &params);
        if (retval) {
            com_err(__func__, retval, "while getting root inode config");
            goto end;
        }
    }

    retval = ext2fs_dir_iterate2(fs, EXT2_ROOT_INO, 0, NULL, walk_dir,
                     &params);
    if (retval) {
        com_err(prog_name, retval != -1 ? retval : params.error, "while interating file system\n");
    }
end:
    free(params.fs_path);
    free(params.se_path);
    return retval;
}

int main(int argc, char *argv[])
{
    int c;
    io_manager io_mgr;
    ext2_filsys fs = NULL;
    errcode_t retval = 0;
    unsigned int block_size = 0;

    add_error_table(&et_ext2_error_table);

    while ((c = getopt (argc, argv, "b:c:em:")) != EOF)
        switch (c) {
        case 'b':
            block_size = strtoul(optarg, NULL, 0);
        case 'c':
            conf_dir = optarg;
            android_configure = 1;
            break;
        case 'e':
            android_sparse_file = 0;
            break;
        case 'm':
            if (*optarg != '/') {
                fprintf(stderr, "Invalid mountpoint %s", optarg);
                exit(EXIT_FAILURE);
            }
            mountpoint = (__u8 *)strdup(optarg);
            break;
        default:
            usage(EXIT_FAILURE);
        }

    if (optind >= argc) {
        fprintf(stderr, "Expected filename after options\n");
        usage(EXIT_FAILURE);
    }

    in_file = strdup(argv[optind++]);

    if (optind >= argc) {
        fprintf(stderr, "Expected directory after options\n");
        usage(EXIT_FAILURE);
    }

    out_dir = strdup(argv[optind++]);

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        usage(EXIT_FAILURE);
    }

    if (android_sparse_file) {
        io_mgr = sparse_io_manager;
        if (asprintf(&in_file, "(%s)", in_file) == -1) {
            fprintf(stderr, "Failed to allocate file name\n");
            exit(EXIT_FAILURE);
        }
    } else
        io_mgr = unix_io_manager;

    retval = ext2fs_open(in_file, EXT2_FLAG_RW, 0, block_size, io_mgr, &fs);
    if (retval) {
        com_err(prog_name, retval, "while opening file %s", in_file);
        exit(EXIT_FAILURE);
    }

    retval = walk_fs(fs);
    if (retval)
        goto end;

    fprintf(stdout, "Extracted filesystem to %s with %u inodes and %u blocks\n",
            out_dir, fs->super->s_inodes_count - fs->super->s_free_inodes_count,
                     fs->super->s_blocks_count - fs->super->s_free_blocks_count -
                     RESERVED_INODES_COUNT);

end:
    retval = ext2fs_close_free(&fs);
    if (retval) {
        com_err(prog_name, retval, "%s",
                "while writing superblocks");
        exit(EXIT_FAILURE);
    }

    remove_error_table(&et_ext2_error_table);
    return 0;
}
