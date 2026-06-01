// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * vim:noexpandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) Panasas Inc., 2011
 * Author: Jim Lieb jlieb@panasas.com
 *
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * -------------
 */

/* handle.c
 * VFS object (file|dir) handle object
 */

#include "config.h"

#include "fsal.h"
#include "fsal_handle_syscalls.h"
#include <libgen.h> /* used for 'dirname' */
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include "fsal_convert.h"
#include "FSAL/fsal_commonlib.h"
#include "FSAL/fsal_localfs.h"
#include "nfs_proto_tools.h"
#include "vfs_methods.h"
#include <os/subr.h>

int vfs_readlink(struct vfs_fsal_obj_handle *myself, fsal_errors_t *fsal_error)
{
	int retval = 0;
	int fd = -1;
	ssize_t retlink;
	struct stat st;
#ifndef __FreeBSD__
	int flags = O_PATH | O_NOACCESS | O_NOFOLLOW;
#endif

	if (myself->u.symlink.link_content != NULL) {
		gsh_free(myself->u.symlink.link_content);
		myself->u.symlink.link_content = NULL;
		myself->u.symlink.link_length = 0;
	}

#ifndef __FreeBSD__
	fd = vfs_fsal_open(myself, flags, fsal_error);
	if (fd < 0)
		return fd;

	retval = vfs_stat_by_handle(fd, &st);
	if (retval < 0)
		goto error;
#else
	struct fhandle *handle = v_to_fhandle(myself->handle->handle_data);

	retval = fhstat(handle, &st);
	if (retval < 0)
		goto error;
#endif

	/* Make room for NUL termination */
	myself->u.symlink.link_content = gsh_malloc(st.st_size + 1);

#if USE_FSAL_VFS_INODE_HANDLES
	char full_path[PATH_MAX];
	dev_t target_dev;
	ino_t target_ino;
	if (vfs_inode_handle_decode(myself->handle, &target_dev, &target_ino) <
	    0) {
		*fsal_error = posix2fsal_error(EINVAL);
		return -EINVAL;
	}

	const char *export_path = op_ctx_export_path(op_ctx);
	if (!export_path || export_path[0] == '\0') {
		LogWarn(COMPONENT_FSAL, "vfs_readlink: empty export path");
		*fsal_error = ERR_FSAL_SERVERFAULT;
		return -EINVAL;
	}

	if (vfs_find_path_by_inode(export_path, target_dev, target_ino,
				   full_path) < 0) {
		retval = -errno;
		LogDebug(
			COMPONENT_FSAL,
			"vfs_readlink: inode search failed (dev=%lu ino=%lu): %s",
			(unsigned long)target_dev, (unsigned long)target_ino,
			strerror(errno));
		*fsal_error = posix2fsal_error(errno);
		return retval;
	}

	retlink = vfs_readlink_by_handle(myself->handle, AT_FDCWD, full_path,
					 myself->u.symlink.link_content,
					 st.st_size);
#else
	/* readlink fills the buffer up to specified size, not NUL terminated,
	 * return is the number of bytes read.
	*/
	retlink = vfs_readlink_by_handle(myself->handle, fd, "",
					 myself->u.symlink.link_content,
					 st.st_size);
#endif

	if (retlink < 0)
		goto error;

	/* Make sure the string is NUL terminated */
	myself->u.symlink.link_content[retlink] = '\0';
	myself->u.symlink.link_length = retlink;
#ifndef __FreeBSD__
	close(fd);
#endif

	return retval;

error:
	retval = -errno;
	*fsal_error = posix2fsal_error(errno);
#ifndef __FreeBSD__
	close(fd);
#endif
	if (myself->u.symlink.link_content != NULL) {
		gsh_free(myself->u.symlink.link_content);
		myself->u.symlink.link_content = NULL;
		myself->u.symlink.link_length = 0;
	}
	return retval;
}

int vfs_get_root_handle(struct fsal_filesystem *fs, struct vfs_fsal_export *exp,
			int *root_fd)
{
	int retval = 0;

	*root_fd = open(fs->path, O_RDONLY | O_DIRECTORY);

	if (*root_fd < 0) {
		retval = errno;
		LogMajor(COMPONENT_FSAL,
			 "Could not open VFS mount point %s: rc = %s (%d)",
			 fs->path, strerror(retval), retval);
		return retval;
	}

	/* Check if we have to re-index the fsid based on config */
	if (exp->fsid_type != FSID_NO_TYPE && exp->fsid_type != fs->fsid_type) {
		retval = -change_fsid_type(fs, exp->fsid_type);

		if (retval != 0) {
			LogCrit(COMPONENT_FSAL,
				"Can not change fsid type of %s to %d, error %s",
				fs->path, exp->fsid_type, strerror(retval));
			(void)close(*root_fd);
			*root_fd = -1;
			return retval;
		}

		LogInfo(COMPONENT_FSAL,
			"Reindexed filesystem %s to fsid=0x%016" PRIx64
			".0x%016" PRIx64,
			fs->path, fs->fsid.major, fs->fsid.minor);
	}

	/* May reindex for some platforms */
	return vfs_re_index(fs, exp);
}
