#ifndef E2FSTOOL_H_INC
#define E2FSTOOL_H_INC
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <support/nls-enable.h>
#include <e2p/e2p.h>
#include <ext2fs/ext2fs.h>

#ifdef ANDROID
#include <private/android_filesystem_capability.h>
#else
/*	This is a dummy implementation, consider having
	private/android_filesystem_capability.h included */
#warning "dummy implementation for capability xattrs"
#define VFS_CAP_U32 2
struct vfs_cap_data {
    __le32 magic_etc;
    struct {
        __le32 permitted;
        __le32 inheritable;
    } data[VFS_CAP_U32];
};
#define cap_valid(x) ((x) >= 0)
#endif

#ifdef SVB_WIN32
#include "windows.h"
#endif

#ifndef XATTR_SELINUX_SUFFIX
#define XATTR_SELINUX_SUFFIX  "selinux"
#endif
#ifndef XATTR_CAPS_SUFFIX
#define XATTR_CAPS_SUFFIX     "capability"
#endif

#define FILE_MODE_MASK 0x0FFF
#define RESERVED_INODES_COUNT 0xA /* Excluding EXT2_ROOT_INO */
#define SYMLINK_I_BLOCK_MAX_SIZE 0x3D

struct inode_params {
	ext2_filsys fs;
	char *path;
	char *filename;
	char *out;
	__u8 *mountpoint;
	FILE *fsconfig;
	FILE *seconfig;
	errcode_t error;
};

static char *absolute_path(const char *file)
{
	char *ret;
	char cwd[PATH_MAX];
#ifndef SVB_WIN32
	if (file[0] != '/') {
#else
	if (file[1] != ':') {
#endif
		if (getcwd(cwd, PATH_MAX) == NULL) {
			fprintf(stderr, "Failed to getcwd\n");
			exit(EXIT_FAILURE);
		}
		ret = malloc(strlen(cwd) + 1 + strlen(file) + 1);
		if (ret)
#ifndef SVB_MINGW
			sprintf(ret, "%s/%s", cwd, file);
#else
	        sprintf(ret, "%s\\%s", cwd, file);
#endif
	} else
		ret = strdup(file);

	return ret;
}

#ifdef SVB_WIN32
#define SYMLINK_ID	"!<symlink>\xff\xfe"
#define SYMLINK_PAD "\x0"
static int _symlink(char *target, const char *file)
{
	int retval, pad = 0;

	FILE *lnk = fopen(absolute_path(file), "wb");
    if (!lnk) {
		retval = errno;
		fprintf(stderr, "Error creating %s\n", file);
		goto end;
	}

    retval = fprintf(lnk, SYMLINK_ID);
	if (retval < 0) {
		retval = errno;
		fprintf(stderr, "Error writing to %s\n", file);
		goto err;
	}
	
	if (strchr(target, '/'))
		pad = 1;

	char *c = target;
	while(*c && !(retval < 0))
		if (pad)
			retval = fprintf(lnk, "%c%c", *c++, 0);
		else
			retval = fprintf(lnk, "%c", *c++);

	if (retval < 0) {
		retval = errno;
		fprintf(stderr, "Error writing to %s\n", file);
		goto err;
	}

	retval = fwrite(SYMLINK_PAD , 1, sizeof(SYMLINK_PAD), lnk);

	if (retval < 0) {
		retval = errno;
		fprintf(stderr, "Error writing to %s\n", file);
		goto err;
	}

	if (!SetFileAttributes(file, FILE_ATTRIBUTE_SYSTEM)) {
		fprintf(stderr, "Error setting attributes to %s\n", file);
		retval = 1;
	}

err:
	retval = fclose(lnk);
	if (retval < 0)
		retval |= errno;
end:
	return retval;
}
#endif

#endif /* E2FSTOOL_H_INC */