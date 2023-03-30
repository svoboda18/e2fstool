#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <getopt.h>
#include <string.h>

#include "e2fstool.h"

static ext2_filsys fs = NULL;
static struct ext2fs_numeric_progress_struct progress;

const char *prog_name = "e2fstool";
char *in_file = NULL;
char *out_dir = NULL;
char *conf_dir = NULL;
__u8 *mountpoint = NULL;
unsigned int android_configure = 0;
unsigned int android_sparse_file = 1;
unsigned int quiet = 0;
unsigned int verbose = 0;

void usage(int ret)
{
    fprintf(stderr, "%s [-c config_dir] [-m mountpoint]\n"
            "\t [-b blocksize] [-hqlvV] filename [directory]\n",
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
    errcode_t retval = ino_get_xattr(fs, ino, "security." XATTR_SELINUX_SUFFIX, val, val_len);

    return retval == EXT2_ET_EA_KEY_NOT_FOUND ? 0 : retval;
}

errcode_t ino_get_capabilities_xattr(ext2_filsys fs, ext2_ino_t ino,
               uint64_t *cap)
{
    errcode_t retval;
    struct vfs_cap_data *cap_data = NULL;
    size_t len = 0;

    assert(cap);
    *cap = 0;

    retval = ino_get_xattr(fs, ino, "security." XATTR_CAPS_SUFFIX, (void **)&cap_data, &len);
    if (retval) {
        goto end;
    }

    if (len == XATTR_CAPS_SZ &&
        cap_data &&
        cap_data->magic_etc & VFS_CAP_REVISION) {
        *cap = cap_data->data[1].permitted;
        *cap <<= 32;
        *cap |= cap_data->data[0].permitted;
        *cap &= VFS_CAP_FLAGS_MASK;
    } else if (cap_data) {
        fprintf(stderr, "%s: Unknown capabilities revision 0x%x\n", __func__, cap_data->magic_etc & VFS_CAP_REVISION_MASK);
    }

end:
    return retval == EXT2_ET_EA_KEY_NOT_FOUND ? 0 : retval;
}

errcode_t ino_get_config(ext2_ino_t ino, struct ext2_inode inode, char *path, void *priv_data)
{
    char *ctx = NULL;
    FILE *contexts, *filesystem;
    size_t ctx_len;
    uint64_t cap;
    struct inode_params *params = (struct inode_params *)priv_data;
    errcode_t retval = 0;

    contexts = fopen(params->se_path, "a");
    if (!contexts)
        goto end;

    filesystem = fopen(params->fs_path, "a");
    if (!filesystem) {
        retval = -1;
        goto err;
    }

    retval = ino_get_selinux_xattr(params->fs, ino, (void **)&ctx, &ctx_len);
    if (retval)
        return retval;

    retval = ino_get_capabilities_xattr(params->fs, ino, &cap);
    if (retval)
        return retval;


    if (ino == EXT2_ROOT_INO) {
        fprintf(filesystem, "/ %u %u %o capabilities=%lu\n", inode.i_uid, inode.i_gid, inode.i_mode & FILE_MODE_MASK, cap);
    } else {
        fprintf(filesystem, "%s %u %u %o capabilities=%lu\n", path, inode.i_uid, inode.i_gid, inode.i_mode & FILE_MODE_MASK, cap);
    }

    if (ctx) {
        if (ino == EXT2_ROOT_INO) {
            path[0] ? fprintf(contexts, "(/.*)? %.*s\n", ctx_len, ctx)
                    : fprintf(contexts, "/%s(/.*)? %.*s\n", path, ctx_len, ctx);
        } else {
            fprintf(contexts, "/%s %.*s\n", path, ctx_len, ctx);
        }
    }

    fclose(filesystem);
err:
    fclose(contexts);
end:
#define ERROR_MESSAGE "while getting config for inode %u"
    if (retval) {
        if (retval != -1) {
            fprintf(stderr, "%s: %s" ERROR_MESSAGE, __func__, strerror(errno), ino);
        } else {
	    com_err(__func__, retval, ERROR_MESSAGE, ino);
	}
    }
#undef ERROR_MESSAGE
    return retval;
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

errcode_t ino_extract_regular(ext2_filsys fs, ext2_ino_t ino, const char *path)
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
                if (errno & (EINTR | EAGAIN)) {
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

        retval = !params->mountpoint[0]
               ? asprintf(&config_path, "%.*s", filename_len - 1, params->filename + 1)
               : asprintf(&config_path, "%s%.*s", params->mountpoint, filename_len, params->filename);
        if (retval < 0 || !config_path) {
            params->error = EXT2_ET_NO_MEMORY;
            goto err;
        }

        retval = ino_get_config(de->inode, inode, config_path, params);
        free(config_path);

        if (retval)
            goto err;
    }

    if (dir == EXT2_ROOT_INO &&
        !strncmp(de->name, "lost+found", name_len)) goto err;

    if (!quiet && verbose)
        fprintf(stdout, "Extracting %s\n", params->filename + 1);
    else if (!quiet)
        ext2fs_numeric_progress_update(params->fs, &progress, de->inode);

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
            retval = ino_extract_regular(params->fs, de->inode, output_file);
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
            fprintf(stderr, "%s: warning: unknown entry \"%s\" (%x)\n", __func__, params->filename, inode.i_mode & LINUX_S_IFMT);
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

    retval = mkdir(out_dir, inode.i_mode);
    if (retval == -1 && errno != EEXIST) {
        fprintf(stderr, "%s: %s while creating %s\n", __func__, strerror(errno), out_dir);
        return errno;
    }

    if (android_configure) {
        if (mountpoint)
            params.mountpoint = mountpoint;
        else if (fs->super->s_last_mounted[0])
            params.mountpoint = fs->super->s_last_mounted;
        else if (fs->super->s_volume_name[0])
            params.mountpoint = fs->super->s_volume_name;
        else
            params.mountpoint = (__u8 *)out_dir;

        if (*params.mountpoint == '/') ++params.mountpoint;

        retval = mkdir(conf_dir, S_IRWXU | S_IRWXG | S_IRWXO);
        if (retval == -1 && errno != EEXIST) {
            fprintf(stderr, "%s: %s while creating %s\n", __func__, strerror(errno), conf_dir);
            return errno;
        }

        if (asprintf(&params.fs_path, "%s/filesystem_config.fs", conf_dir) < 0 ||
            asprintf(&params.se_path, "%s/selinux_contexts.fs", conf_dir) < 0) {
            com_err(__func__, EXT2_ET_NO_MEMORY, "while configuring config paths");
            return 1;
        }

        unlink(params.fs_path);
        unlink(params.se_path);

        retval = ino_get_config(EXT2_ROOT_INO, inode, (char *)params.mountpoint, &params);
        if (retval)
            goto end;
    }

    if (!quiet && !verbose)
        ext2fs_numeric_progress_init(fs, &progress,
                     "Extracting filesystem inodes: ",
                     fs->super->s_inodes_count - fs->super->s_free_inodes_count - RESERVED_INODES_COUNT);

    retval = ext2fs_dir_iterate2(fs, EXT2_ROOT_INO, 0, NULL, walk_dir,
                     &params);
    if (retval) {
        com_err(prog_name, retval != -1 ? retval : params.error, "while interating file system\n");
    }

    if (!quiet && !verbose)
        ext2fs_numeric_progress_close(fs, &progress, "done\n");
end:
    free(params.fs_path);
    free(params.se_path);

    return retval;
}

int main(int argc, char *argv[])
{
    int c, show_version_only = 0, ls = 0;
    io_manager io_mgr = unix_io_manager;
    errcode_t retval = 0;
    unsigned int b, blocksize = 0;

    add_error_table(&et_ext2_error_table);

    while ((c = getopt (argc, argv, "b:c:ehm:qlvV")) != EOF) {
        switch (c) {
        case 'b':
            blocksize = parse_num_blocks2(optarg, -1);
            b = (blocksize > 0) ? blocksize : -blocksize;
            if (b < EXT2_MIN_BLOCK_SIZE ||
                b > EXT2_MAX_BLOCK_SIZE) {
                com_err(prog_name, 0,
                    "invalid block size - %s", optarg);
                exit(EXIT_FAILURE);
            }
            if (blocksize > 4096)
                fprintf(stderr, "Warning: blocksize %d not "
                          "usable on most systems.\n",
                    blocksize);
            break;
        case 'c':
            conf_dir = strdup(optarg);
            ++android_configure;
            break;
        case 'e':
            --android_sparse_file;
            break;
        case 'm':
            if (*optarg != '/') {
                fprintf(stderr, "Invalid mountpoint %s", optarg);
                exit(EXIT_FAILURE);
            }
            mountpoint = (__u8 *)strdup(optarg);
            break;
        case 'h':
            usage(EXIT_SUCCESS);
        case 'q':
            ++quiet;
            break;
        case 'l':
            ++ls;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            ++show_version_only;
            break;
        default:
            usage(EXIT_FAILURE);
        }
    }

    if (!show_version_only) {
        if (optind >= argc) {
            fprintf(stderr, "Expected filename after options\n");
            usage(EXIT_FAILURE);
        }

        in_file = strdup(argv[optind++]);

        if (!ls) {
            if (optind >= argc) {
                fprintf(stderr, "Expected directory after options\n");
                usage(EXIT_FAILURE);
            }

            out_dir = strdup(argv[optind++]);
        }
	
	if (optind < argc) {
            fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
            usage(EXIT_FAILURE);
        }
    }

    if (!quiet || show_version_only)
        fprintf (stderr, "e2fstool %s (%s)\n\n", E2FSTOOL_VERSION,
             E2FSTOOL_DATE);

    if (show_version_only) {
        fprintf(stderr, "Using %s\n",
            error_message(EXT2_ET_BASE));
        exit(EXIT_SUCCESS);
    }

    if (!quiet) {
        fprintf(stderr, "Opening image file");
        if (blocksize)
            fprintf(stderr, " with blocksize of %u", blocksize);
        fputs(": ", stderr);
    }

    if (android_sparse_file) {
        io_mgr = sparse_io_manager;
        if (asprintf(&in_file, "(%s)", in_file) == -1) {
            fprintf(stderr, "Failed to allocate file name\n");
            exit(EXIT_FAILURE);
        }
    }

    retval = ext2fs_open(in_file, EXT2_FLAG_64BITS | EXT2_FLAG_EXCLUSIVE |
                                  EXT2_FLAG_THREADS | EXT2_FLAG_PRINT_PROGRESS, 0, blocksize, io_mgr, &fs);
    if (retval) {
        fputs("\n\n", stderr);
        com_err(prog_name, retval, "while opening file %s, try to increase your page/swap file.", in_file);
        exit(EXIT_FAILURE);
    }

    fputs("done\n", stderr);

    if (verbose || ls) {
        list_super2(fs->super, stderr);
        fprintf(stderr, "\n");
    }
    if (ls)
        goto end;

    retval = walk_fs(fs);
	if (retval)
        goto end;

    fprintf(stdout, "\nWritten %u inodes (%u blocks) to \"%s\"\n",
            fs->super->s_inodes_count - fs->super->s_free_inodes_count,
            fs->super->s_blocks_count - fs->super->s_free_blocks_count -
            RESERVED_INODES_COUNT, out_dir);
end:
    retval = ext2fs_close_free(&fs);
    if (retval) {
        com_err(prog_name, retval, "%s",
                "while writing superblocks");
        exit(EXIT_FAILURE);
    }

    free(in_file);
    free(out_dir);
    free(conf_dir);
    free(mountpoint);
    remove_error_table(&et_ext2_error_table);
    return EXIT_SUCCESS;
}
