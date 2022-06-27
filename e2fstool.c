#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <getopt.h>
#include <string.h>

#include "e2fstool.h"

static const char * prog_name = "e2fstool";
static char *in_file;
static char *out_dir;
static char *conf_dir;
static __u8 *mountpoint = NULL;
static int android_configure;
static int android_sparse_file = 1;

static int _symlink(char *target, const char *file);

static void usage(int ret)
{
	fprintf(stderr, "%s [-c config_dir] [-m mountpoint]\n"
					"\t img_file out_dir\n",
					prog_name);
	exit(ret);
}

static errcode_t ino_get_xattr(ext2_filsys fs, ext2_ino_t ino, const char *key, void **val, size_t *val_len)
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
		return retval ? retval : close_retval;
	}
	return retval;
}

static errcode_t ino_get_selinux_xattr(ext2_filsys fs, ext2_ino_t ino,
			   void **val, size_t *val_len)
{
	errcode_t retval;

	retval = ino_get_xattr(fs, ino, "security." XATTR_SELINUX_SUFFIX, val, val_len);
	
	if (retval == EXT2_ET_EA_KEY_NOT_FOUND)
		return 0;
	else 
		return retval;
}

static errcode_t ino_get_capabilities_xattr(ext2_filsys fs, ext2_ino_t ino,
			   uint64_t *val)
{
	errcode_t retval;
	struct vfs_cap_data *cap_data;
	size_t len;
	uint64_t cap = 0;
	
	retval = ino_get_xattr(fs, ino, "security." XATTR_CAPS_SUFFIX, (void **)&cap_data, &len);
	if (retval)
		goto end;

	if (cap_data->magic_etc & VFS_CAP_REVISION_2) {
		cap = cap_data->data[0].permitted & 0xffffffff;
		if ((cap >> 32) != cap_data->data[1].permitted || !cap_valid(cap))
			cap = 0;
	} else {
		retval = 1;
		fprintf(stderr, "Invalid cap xattrs magic for %d\n", ino);
	}

end:
	*val = cap;

	if (retval == EXT2_ET_EA_KEY_NOT_FOUND)
		return 0;
	else 
		return retval;
}

static errcode_t ino_get_config(ext2_filsys fs, ext2_ino_t ino, struct ext2_inode inode, char *path, void *priv_data)
{
	char *sel = NULL;
	uint64_t cap;
	size_t sel_len;
	struct inode_params *params = (struct inode_params *)priv_data;
	unsigned int is_root = path == (char *)params->mountpoint;
	errcode_t retval = 0;
	
	retval = ino_get_selinux_xattr(fs, ino, (void **)&sel, &sel_len);
	if (retval) {
		com_err(__func__, retval, "while reading root inode xattrs");
		return retval;
	}

	retval = ino_get_capabilities_xattr(fs, ino, &cap);
	if (retval) {
		com_err(__func__, retval, "while reading root inode xattrs");
		return retval;
	}

	if (is_root)
		retval = fprintf(params->fsconfig, "/ %u %u %o capabilities=%lu\n", inode.i_uid, inode.i_gid, inode.i_mode & FILE_MODE_MASK, cap);
	else
		retval = fprintf(params->fsconfig, "%s %u %u %o capabilities=%lu\n", path,
						inode.i_uid, inode.i_gid, inode.i_mode & FILE_MODE_MASK, cap);
	if (retval < 0) 
		return errno;

	if (sel) {
		if (is_root)
			if (*path == '\0')
				retval = fprintf(params->seconfig, "(/.*)? %.*s\n", sel_len, sel);
			else
				retval = fprintf(params->seconfig, "/%s(/.*)? %.*s\n", path, sel_len, sel);
		else
			retval = fprintf(params->seconfig, "/%s %.*s\n", path, sel_len, sel);
	}
	if (retval < 0)
		return errno;

	return 0;
}

static errcode_t ino_get_symlink_buf(ext2_filsys fs, ext2_ino_t ino, struct ext2_inode *inode,
			  const char *path)
{
	ext2_file_t e2_file;
	char *link_target = NULL;
	__u32 i_size = inode->i_size;
	errcode_t retval = 0;

	link_target = malloc(i_size + 1);
	if (!link_target) {
		com_err(__func__, errno, "while allocating memory");
		return ENOMEM;
	}

	if (i_size < SYMLINK_I_BLOCK_MAX_SIZE)
		strncpy(link_target, (char *) inode->i_block, i_size);
	else {
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
#ifndef SVB_WIN32
	retval = symlink(link_target, path);
#else
	retval = _symlink(link_target, path);
#endif
	if (retval == -1) {
		com_err(__func__, errno, "while creating symlink %s -> %s", link_target, path);
		retval = errno;
	}

end:
	free(link_target);
	if (retval)
		com_err(__func__, retval, "while creating symlink %s", path);
	return retval;
}

static errcode_t ino_get_file_buf(ext2_filsys fs, ext2_ino_t ino, const char *path)
{
	ext2_file_t	e2_file;
	char *buf = NULL;
	int	fd, nbytes;
	unsigned int got;
	blk64_t blocksize = fs->blocksize;
	errcode_t retval = 0, close_retval = 0;
	
	fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (fd < 0) {
		com_err(__func__, errno, "while creating file");
		return errno;
	}

	retval = ext2fs_file_open(fs, ino, 0, &e2_file);
	if (retval) {
		com_err(__func__, retval, "while opening ext2 file");
		goto end;
	}
	
	retval = ext2fs_get_mem(blocksize, &buf);
	if (retval) {
		com_err(__func__, retval, "while allocating memory");
		goto end;
	}
	
	while (1) {
		retval = ext2fs_file_read(e2_file, buf, blocksize, &got);
		if (retval) {
			com_err(__func__, retval, "while reading ext2 file");
			goto quit;
		}
		if (got == 0)
			break;
		nbytes = write(fd, buf, got);
		if (nbytes < 0 || (unsigned)nbytes != got) {
			com_err(__func__, errno, "while writing file\n");
			goto close;
		}
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

static int walk_dir(ext2_ino_t dir,
			int flags EXT2FS_ATTR((unused)),
			struct ext2_dir_entry *de,
			int offset EXT2FS_ATTR((unused)),
			int blocksize EXT2FS_ATTR((unused)),
			char *buf EXT2FS_ATTR((unused)), void *priv_data)
{
	__u16 nlen, flen;
	char *path;
	struct ext2_inode inode;
	struct inode_params *params = (struct inode_params *)priv_data;
	errcode_t retval = 0;
	int ret = 0;
	
	nlen = de->name_len & 0xff;
	if (!strncmp(de->name, ".", nlen)
		|| (!strncmp(de->name, "..", nlen)))
		return 0;

	flen = asprintf(&params->filename, "%s/%.*s", params->path, nlen,
			de->name);
	if (flen < 0) {
		params->error = ENOMEM;
		return -ENOMEM;
	}
	
	if (asprintf(&path, "%s%.*s", params->out, flen,
				params->filename) < 0) {
		params->error = ENOMEM;
		goto end;
	}
	
	retval = ext2fs_read_inode(params->fs, de->inode, &inode);
	if (retval) {
		com_err(__func__, retval, "while reading inode %u", de->inode);
		goto err;
	}
	
	if (android_configure) {
		char *out;

		if (*params->mountpoint == '\0')
			ret = asprintf(&out, "%.*s", flen - 1,
				params->filename + 1);
		else
			ret = asprintf(&out, "%s%.*s", params->mountpoint, flen,
				params->filename);
		if (ret < 0) {
			params->error = ENOMEM;
			goto err;
		}
		
		retval = ino_get_config(params->fs, de->inode, inode, out, params);
		free(out);
		if (retval) {
			com_err(__func__, retval, "while getting inode %u config", de->inode);
			goto err;
		}
	}

	if (dir == EXT2_ROOT_INO &&
		!strncmp(de->name, "lost+found", nlen)) goto err;
			

	switch(inode.i_mode & LINUX_S_IFMT) {
		case LINUX_S_IFCHR:
		case LINUX_S_IFBLK:
		case LINUX_S_IFIFO:
#if !defined(_WIN32) || defined(SVB_WIN32)
#if defined(S_IFSOCK) && !defined(SVB_WIN32)
		case LINUX_S_IFSOCK:
#endif
		case LINUX_S_IFLNK:
			retval = ino_get_symlink_buf(params->fs, de->inode, &inode, path);
			if (retval)
				com_err(__func__, errno, "while creating symlink %s", path);
			break;
#endif
		case LINUX_S_IFREG:
			retval = ino_get_file_buf(params->fs, de->inode, absolute_path(path));
			if (retval)
				com_err(__func__, retval, "while writing file %s", path);
			break;
		case LINUX_S_IFDIR: ;
			char *cur_path = params->path;
			char *cur_filename = params->filename;
			params->path = params->filename;
#ifndef SVB_MINGW
			retval = mkdir(absolute_path(path), S_IRWXU | S_IRWXG | S_IRWXO);
#else
			retval = _mkdir(absolute_path(path));
#endif
			if (retval == -1 && errno != EEXIST) {
				fprintf(stderr, "Unexpected error while extracting %s\n", path);
				retval = errno;
				goto err;
			}

			retval = ext2fs_dir_iterate2(params->fs, de->inode, 0, NULL,
							 walk_dir, params);
			if (retval)
				goto err;

			params->path = cur_path;
			params->filename = cur_filename;
			break;
		default:
			com_err(__func__, 0, "Unknown entry \"%s\" (%x)", params->filename, inode.i_mode & LINUX_S_IFMT);
			retval = -1;
	}

err:
	free(path);
end:
	free(params->filename);
	params->error |= retval;
	return retval;
}

static errcode_t walk_fs(ext2_filsys fs)
{
	struct ext2_inode inode;
	char *sec, *fsc;
	struct inode_params params = {
		.fs = fs,
		.path = "",
		.filename = "",
		.mountpoint = NULL,
		.fsconfig = NULL,
		.seconfig = NULL,
		.out = out_dir,
		.error = 0
	};
	errcode_t retval = 0;
	
	retval = ext2fs_read_inode(fs, EXT2_ROOT_INO, &inode);
	if (retval) {
		com_err(__func__, retval, "while reading root inode");
		return retval;
	}
	
#ifndef SVB_MINGW
	retval = mkdir(absolute_path(out_dir), S_IRWXU | S_IRWXG | S_IRWXO);
#else
	retval = _mkdir(absolute_path(out_dir));
#endif
	if (retval == -1 && errno != EEXIST) {
		fprintf(stderr, "Unexpected errror while extracting %s\n", out_dir);
		return errno;
	}

	if (android_configure) {
		if (mountpoint)
			params.mountpoint = mountpoint;
		else if (fs->super->s_volume_name)
			params.mountpoint = fs->super->s_volume_name;
		else if (fs->super->s_last_mounted)
			params.mountpoint = fs->super->s_last_mounted;
		else
			params.mountpoint = (__u8 *)out_dir;
		
		if (*params.mountpoint == '/') ++params.mountpoint;
		
#ifndef SVB_MINGW
		retval = mkdir(absolute_path(conf_dir), S_IRWXU | S_IRWXG | S_IRWXO);
#else
		retval = _mkdir(absolute_path(conf_dir));
#endif
		if (retval == -1 && errno != EEXIST) {
			fprintf(stderr, "Unexpected errror while creating %s\n", conf_dir);
			return errno;
		}

		if (asprintf(&fsc, "%s/fs_config.fs", conf_dir) < 0)
			return ENOMEM;
		if (asprintf(&sec, "%s/se_config.fs", conf_dir) < 0)
			return ENOMEM;
		
		params.fsconfig = fopen(fsc, "w");
		if (!params.fsconfig) {
			fprintf(stderr, "Unexpected errror while opening %s\n", fsc);
			return errno;
		}

		params.seconfig = fopen(sec, "w");
		if (!params.seconfig) {
			fprintf(stderr, "Unexpected errror while opening %s\n", sec);
			params.error = errno;
			goto fsclose;
		}
		
		retval = ino_get_config(fs, EXT2_ROOT_INO, inode, (char *)params.mountpoint, &params);
		if (retval) {
			com_err(__func__, retval, "while getting root inode config");
			goto end;
		}
	}
	
	retval = ext2fs_dir_iterate2(fs, EXT2_ROOT_INO, 0, NULL, walk_dir,
				     &params);
	if (retval) {
		com_err(prog_name, retval, "while interating file system\n");
		params.error = retval;
	}

end:
	if (android_configure)
		fclose(params.seconfig);
fsclose:
	if (android_configure)
		fclose(params.fsconfig);

	return params.error;
}

int main(int argc, char *argv[])
{
	int c;
	io_manager io_mgr;
	ext2_filsys fs = NULL;
	errcode_t retval = 0;
	
	add_error_table(&et_ext2_error_table);

	while ((c = getopt (argc, argv, "c:em:")) != EOF) {
		switch (c) {
		case 'c':
			conf_dir = absolute_path(optarg);
			android_configure = 1;
			break;
		case 'e':
			android_sparse_file = 0;
			break;
		case 'm':
			mountpoint = (__u8 *)strdup(optarg);
			break;
		default:
			usage(EXIT_FAILURE);
		}
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
	} else {
		io_mgr = unix_io_manager;
	}

	retval = ext2fs_open(in_file, EXT2_FLAG_RW, 0, 0, io_mgr, &fs);
	if (retval) {
		com_err(prog_name, retval, "while opening file %s", in_file);
		exit(EXIT_FAILURE);
	}

	retval = walk_fs(fs);
	if (retval) {
		com_err(prog_name, retval, "while walking filesystem");
		goto end;
	}

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
