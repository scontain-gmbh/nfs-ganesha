// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *   Copyright (C) International Business Machines  Corp., 2010
 *   Author(s): Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 *   This library is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published
 *   by the Free Software Foundation; either version 2.1 of the License, or
 *   (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/**
 * @file FSAL/FSAL_VFS/os/linux/handle_syscalls.c
 * @brief System calls for the Linux handle calls
 *
 */

#include "fsal.h"
#include "fsal_api.h"
#include "fsal_convert.h"
#include "FSAL/fsal_commonlib.h"
#include "../../vfs_methods.h"

#ifdef USE_FSAL_VFS_INODE_HANDLES

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#include "nfs_proto_tools.h"

#define INODE_CACHE_BITS 8u
#define INODE_CACHE_SIZE (1u << INODE_CACHE_BITS)
#define INODE_CACHE_MASK (INODE_CACHE_SIZE - 1u)

typedef struct {
	dev_t dev;
	ino_t ino;
	bool valid;
	char path[PATH_MAX];
} inode_cache_entry_t;

static struct {
	inode_cache_entry_t slots[INODE_CACHE_SIZE];
	pthread_rwlock_t lock;
} g_inode_cache = { .lock = PTHREAD_RWLOCK_INITIALIZER };

/*
 * Knuth / Fibonacci multiplicative hash.  XOR-mixes the (dev, ino) pair
 * into INODE_CACHE_BITS wide index; much better distribution than a
 * simple modulo on small integers.
 */
static inline size_t inode_cache_idx(dev_t dev, ino_t ino)
{
	uint64_t h = (uint64_t)dev * UINT64_C(11400714819323198485) ^
		     (uint64_t)ino * UINT64_C(6364136223846793005);
	return (size_t)(h >> (64u - INODE_CACHE_BITS)) & INODE_CACHE_MASK;
}

/*
 * icache_lookup — cache read.
 *
 * Returns 0 and writes the absolute path into path_out on a validated
 * hit.  Returns -1 on any miss or stale entry.
 *
 * The copy of the path string happens inside the read lock; the
 * validating lstat() runs outside the lock to avoid holding a lock
 * during a syscall.
 */
static int icache_lookup(dev_t dev, ino_t ino, char *path_out)
{
	size_t idx = inode_cache_idx(dev, ino);
	char tmp[PATH_MAX];
	struct stat st;
	bool hit;

	pthread_rwlock_rdlock(&g_inode_cache.lock);
	const inode_cache_entry_t *e = &g_inode_cache.slots[idx];
	hit = e->valid && e->dev == dev && e->ino == ino;
	if (hit)
		memcpy(tmp, e->path, PATH_MAX);
	pthread_rwlock_unlock(&g_inode_cache.lock);

	if (!hit)
		return -1;

	/*
	 * Validate outside the lock.  lstat() (not stat()) so a symlink
	 * is matched by its own inode rather than the target's — consistent
	 * with AT_SYMLINK_NOFOLLOW used when the handle was created.
	 *
	 * If the file was renamed between the copy and this lstat, we get a
	 * miss here and the caller falls through to a fresh tree walk.  This
	 * is correct: the next walk will find the new path and update the
	 * cache.
	 */
	if (lstat(tmp, &st) < 0 || st.st_dev != dev || st.st_ino != ino)
		return -1; /* stale */

	memcpy(path_out, tmp, PATH_MAX);
	return 0;
}

/*
 * icache_insert — cache write.
 *
 * Collision silently evicts the old entry; there is no second-chance
 * mechanism.  For correctness we rely solely on the validation in
 * icache_lookup.
 */
static void icache_insert(dev_t dev, ino_t ino, const char *path)
{
	size_t idx = inode_cache_idx(dev, ino);
	inode_cache_entry_t *e = &g_inode_cache.slots[idx];

	pthread_rwlock_wrlock(&g_inode_cache.lock);
	e->dev = dev;
	e->ino = ino;
	e->valid = true;
	strncpy(e->path, path, PATH_MAX - 1);
	e->path[PATH_MAX - 1] = '\0';
	pthread_rwlock_unlock(&g_inode_cache.lock);
}

#endif

/* We can at most support 40 byte handles, which are the largest known.
 * We also expect handles to be at least 4 bytes.
 */
#define VFS_MAX_HANDLE 48
#define VFS_MIN_HANDLE_SIZE 4

/* Visual handle format
 *
 * 1 byte		handle_len (doesn't go on wire)
 * 1 byte		flags
 *				00xxxxxx fsid_type
 *				01000000 handle_type fits in one byte
 *				10000000 handle_type fits in two bytes
 *				11000000 handle_type fits in four bytes
 */
#define HANDLE_TYPE_8 0x40
#define HANDLE_TYPE_16 0x80
#define HANDLE_TYPE_32 0xC0
#define HANDLE_TYPE_MASK 0xC0
#define HANDLE_DUMMY 0x20
#define HANDLE_FSID_MASK (~(HANDLE_TYPE_MASK | HANDLE_DUMMY))
/*
 * 0, 8, or 16 bytes	fsid type
 * 1,2 or 4 bytes	handle type
 * 12 to 40 bytes	opaque kernel handle
 *
 * NOTE: if handle type doesn't fit in 2 bytes or less, 40 byte handles
 *	 (BTRFS and GPFS are known file systems that use 40 bytes) are
 *	 incompatible with 16 byte uuid form fsids.
 *	 If VMware clients are concerned, the limit is 8 bytes less...
 */

int display_vfs_handle(struct display_buffer *dspbuf,
		       struct vfs_file_handle *fh)
{
	int16_t i16;
	int32_t i32;
	uint32_t u32[2];
	uint64_t u64[2];
	uint8_t handle_cursor = 1;
	int b_left;

	b_left = display_printf(dspbuf,
				"Handle len %hhu 0x%02hhx: ", fh->handle_len,
				fh->handle_data[0]);

	if (b_left <= 0)
		return b_left;

	switch ((enum fsid_type)fh->handle_data[0] & HANDLE_FSID_MASK) {
	case FSID_NO_TYPE:
		b_left = display_cat(dspbuf, "no fsid");
		break;

	case FSID_ONE_UINT64:
	case FSID_MAJOR_64:
		memcpy(u64, fh->handle_data + handle_cursor, sizeof(u64[0]));
		handle_cursor += sizeof(u64[0]);
		b_left = display_printf(dspbuf,
					"fsid=0x%016" PRIx64
					".0x0000000000000000",
					u64[0]);
		break;

	case FSID_TWO_UINT64:
		memcpy(u64, fh->handle_data + handle_cursor, sizeof(u64));
		handle_cursor += sizeof(u64);
		b_left = display_printf(dspbuf,
					"fsid=0x%016" PRIx64 ".0x%016" PRIx64,
					u64[0], u64[1]);
		break;

	case FSID_TWO_UINT32:
	case FSID_DEVICE:
		memcpy(u32, fh->handle_data + handle_cursor, sizeof(u32));
		handle_cursor += sizeof(u32);
		b_left = display_printf(dspbuf,
					"fsid=0x%016" PRIx32 ".0x%016" PRIx32,
					u32[0], u32[1]);
		break;
	}

	if (b_left <= 0)
		return b_left;

	if ((fh->handle_data[0] & HANDLE_DUMMY) != 0)
		return display_cat(dspbuf, ", DUMMY");

	switch (fh->handle_data[0] & HANDLE_TYPE_MASK) {
	case 0:
		b_left = display_cat(dspbuf, ", invalid type");
		break;

	case HANDLE_TYPE_8:
		b_left = display_printf(dspbuf, ", type 0x%02hhx",
					fh->handle_data[handle_cursor]);
		handle_cursor++;
		break;
	case HANDLE_TYPE_16:
		memcpy(&i16, fh->handle_data + handle_cursor, sizeof(i16));
		handle_cursor += sizeof(i16);
		b_left = display_printf(dspbuf, ", type 0x%04h" PRIx16, i16);
		break;
	case HANDLE_TYPE_32:
		memcpy(&i32, fh->handle_data + handle_cursor, sizeof(i32));
		handle_cursor += sizeof(i32);
		b_left = display_printf(dspbuf, ", type 0x%04" PRIx32, i32);
		break;
	}

	if (b_left <= 0)
		return b_left;

	b_left = display_cat(dspbuf, ", opaque: ");

	if (b_left <= 0)
		return b_left;

	return display_opaque_value(dspbuf, fh->handle_data + handle_cursor,
				    fh->handle_len - handle_cursor);
}

/* clang-format off */
#define LogVFSHandle(fh)                                                   \
	do {                                                               \
		if (isMidDebug(COMPONENT_FSAL)) {                          \
			char buf[256] = "\0";                              \
			struct display_buffer dspbuf = { sizeof(buf), buf, \
							 buf };            \
									   \
			display_vfs_handle(&dspbuf, fh);                   \
									   \
			LogMidDebug(COMPONENT_FSAL, "%s", buf);            \
		}                                                          \
	} while (0)
/* clang-format on */

#if USE_FSAL_VFS_INODE_HANDLES

static int find_path_recursive(const char *dir_path, dev_t target_dev,
			       ino_t target_ino, char *path_out, int depth)
{
	if (unlikely(!dir_path || depth > 20)) {
		errno = depth > 20 ? ELOOP : EINVAL;
		return -1;
	}

	struct stat st;
	char path_buf[PATH_MAX];
	DIR *dir;
	struct dirent *entry;
	int rc = -1;

	/*
	 * Root self-check: handles the case where the caller is looking
	 * for a directory whose inode happens to be dir_path itself.
	 * This fires on the export root and on every directory-target
	 * lookup.  lstat, not stat, for symlink-inode correctness.
	 */
	if (lstat(dir_path, &st) == 0 && st.st_dev == target_dev &&
	    st.st_ino == target_ino) {
		strncpy(path_out, dir_path, PATH_MAX - 1);
		path_out[PATH_MAX - 1] = '\0';
		return 0;
	}

	dir = opendir(dir_path);
	if (!dir)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		/* ---- Inline dot/dotdot skip ---- */
		if (entry->d_name[0] == '.' &&
		    (entry->d_name[1] == '\0' ||
		     (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
			continue;

		/* ---- d_ino / d_type fast-path classification ---- */
		/*
		 * ino_known: d_ino == 0 means the filesystem did not fill
		 *            it in; treat as "unknown" and do not optimise.
		 * ino_match: d_ino matches — still need lstat to verify dev.
		 * known_dir: d_type == DT_DIR — definitely a directory.
		 * unk_type:  d_type == DT_UNKNOWN — type not provided.
		 */
		const bool ino_known = (entry->d_ino != 0);
		const bool ino_match = ino_known &&
				       ((ino_t)entry->d_ino == target_ino);
		const bool known_dir = (entry->d_type == DT_DIR);
		const bool unk_type = (entry->d_type == DT_UNKNOWN);

		/*
		 * Skip entirely: inode is known, doesn't match, AND the
		 * entry is provably not a directory.  It cannot be the
		 * target and cannot contain it.
		 */
		if (ino_known && !ino_match && !known_dir && !unk_type)
			continue;

		/* Build the absolute child path. */
		int n = snprintf(path_buf, sizeof(path_buf), "%s/%s", dir_path,
				 entry->d_name);
		if (unlikely(n < 0 || n >= (int)sizeof(path_buf)))
			continue;

		/*
		 * Fast directory recursion: d_type confirms it is a
		 * directory, d_ino has already shown it is not the target.
		 * Recurse without lstat; the recursive call's root check
		 * will re-test dir_path at depth+1.
		 */
		if (known_dir && ino_known && !ino_match) {
			if (find_path_recursive(path_buf, target_dev,
						target_ino, path_out,
						depth + 1) == 0) {
				rc = 0;
				break;
			}
			continue;
		}

		/*
		 * lstat is required here because:
		 *   - ino_match: must verify st_dev matches too, and the
		 *     entry may itself be a symlink we should not follow.
		 *   - unk_type:  can't determine if it's a directory
		 *     without a stat call.
		 */
		if (lstat(path_buf, &st) < 0)
			continue;

		if (st.st_dev == target_dev && st.st_ino == target_ino) {
			strncpy(path_out, path_buf, PATH_MAX - 1);
			path_out[PATH_MAX - 1] = '\0';
			rc = 0;
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			if (find_path_recursive(path_buf, target_dev,
						target_ino, path_out,
						depth + 1) == 0) {
				rc = 0;
				break;
			}
		}
	}

	closedir(dir);
	if (rc < 0)
		errno = ESTALE;
	return rc;
}

/*
 * vfs_inode_handle_decode
 *
 * Extracts the (dev_t, ino_t) pair from a USE_FSAL_VFS_INODE_HANDLES
 * wire handle into *dev_out and *ino_out.
 *
 * The handle is self-describing: fsid_type lives in the low bits of
 * byte 0, so no external parameter is required.  All three invariants
 * of the inode handle format are validated before any data is read.
 *
 * Wire layout (matches vfs_map_name_to_handle_at exactly):
 *
 *   byte 0              flags:  bits[5:0] = fsid_type  (HANDLE_FSID_MASK)
 *                               bits[7:6] = HANDLE_TYPE_8 (must be 0x40)
 *   bytes [1, fsid_end) encoded fsid  (sizeof_fsid(fsid_type) bytes)
 *   byte  [fsid_end]    synthetic type marker (must be 0xFF)
 *   bytes [fsid_end+1,
 *          fsid_end+1+sizeof(dev_t))   dev_t, host byte order
 *   bytes [fsid_end+1+sizeof(dev_t),
 *          fsid_end+1+sizeof(dev_t)
 *                     +sizeof(ino_t))  ino_t, host byte order
 *
 * Returns  0 on success.
 * Returns -1 with errno = EINVAL on any validation failure.
 */
int vfs_inode_handle_decode(const vfs_file_handle_t *fh, dev_t *dev_out,
			    ino_t *ino_out)
{
	if (unlikely(!fh || !dev_out || !ino_out)) {
		errno = EINVAL;
		return -1;
	}

	/* ---- Validate HANDLE_TYPE bits -------------------------------- */
	if ((fh->handle_data[0] & HANDLE_TYPE_MASK) != HANDLE_TYPE_8) {
		LogDebug(COMPONENT_FSAL,
			 "vfs_inode_handle_decode: unexpected type bits 0x%02x"
			 " (want HANDLE_TYPE_8 = 0x%02x)",
			 fh->handle_data[0] & HANDLE_TYPE_MASK, HANDLE_TYPE_8);
		errno = EINVAL;
		return -1;
	}

	/*
	 * Read fsid_type from the handle itself — not from any caller-
	 * supplied fs pointer.  The handle is authoritative; using an
	 * external value would silently accept a handle created by a
	 * different filesystem export.
	 */
	const enum fsid_type fsid_type =
		(enum fsid_type)(fh->handle_data[0] & HANDLE_FSID_MASK);

	/*
	 * cursor lands on the synthetic type marker.
	 *   +1              skip the flags byte
	 *   +sizeof_fsid()  skip the encoded fsid
	 */
	const uint8_t marker_pos = 1 + sizeof_fsid(fsid_type);

	/* ---- Validate the synthetic type marker ----------------------- */
	if (fh->handle_data[marker_pos] != 0xFF) {
		LogDebug(COMPONENT_FSAL,
			 "vfs_inode_handle_decode: not an inode-based handle"
			 " (marker byte = 0x%02x, want 0xFF)",
			 fh->handle_data[marker_pos]);
		errno = EINVAL;
		return -1;
	}

	/*
	 * First payload byte is immediately after the marker.
	 * Verify the handle is long enough before touching any data.
	 */
	const uint8_t payload = marker_pos + 1;
	const size_t required = payload + sizeof(dev_t) + sizeof(ino_t);

	if (fh->handle_len < required) {
		LogDebug(COMPONENT_FSAL,
			 "vfs_inode_handle_decode: handle too short"
			 " (have %u bytes, need %zu)",
			 fh->handle_len, required);
		errno = EINVAL;
		return -1;
	}

	/* ---- Extract payload ------------------------------------------ */
	memcpy(dev_out, fh->handle_data + payload, sizeof(*dev_out));
	memcpy(ino_out, fh->handle_data + payload + sizeof(*dev_out),
	       sizeof(*ino_out));

	LogFullDebug(COMPONENT_FSAL, "vfs_inode_handle_decode: dev=%lu ino=%lu",
		     (unsigned long)*dev_out, (unsigned long)*ino_out);

	return 0;
}

/* 
 * vfs_find_path_by_inode
 *
 * Public entry point: resolves (target_dev, target_ino) to an
 * absolute path under export_path.
 *
 * Checks the inode cache first.  On a miss, runs the tree walk and
 * populates the cache before returning.
 *
 * Returns 0 and writes at most PATH_MAX bytes into path_out on
 * success.  Returns -1 with errno set on failure.
 * 
 */
int vfs_find_path_by_inode(const char *export_path, dev_t target_dev,
			   ino_t target_ino, char path_out[PATH_MAX])
{
	if (unlikely(!export_path || !path_out)) {
		errno = EINVAL;
		return -1;
	}

	if (icache_lookup(target_dev, target_ino, path_out) == 0) {
		LogFullDebug(COMPONENT_FSAL,
			     "inode cache hit: (%lu,%lu) -> '%s'",
			     (unsigned long)target_dev,
			     (unsigned long)target_ino, path_out);
		return 0;
	}

	if (find_path_recursive(export_path, target_dev, target_ino, path_out,
				0) < 0) {
		LogDebug(COMPONENT_FSAL,
			 "inode not found: (%lu,%lu) under '%s': %s",
			 (unsigned long)target_dev, (unsigned long)target_ino,
			 export_path, strerror(errno));
		return -1;
	}

	icache_insert(target_dev, target_ino, path_out);

	LogDebug(COMPONENT_FSAL, "inode resolved: (%lu,%lu) -> '%s'",
		 (unsigned long)target_dev, (unsigned long)target_ino,
		 path_out);
	return 0;
}

int vfs_map_name_to_handle_at(int fd, struct fsal_filesystem *fs,
			      const char *path, vfs_file_handle_t *fh,
			      int flags)
{
	struct stat st;
	int rc;

	LogDebug(COMPONENT_FSAL,
		 "vfs_map_name_to_handle_at: fd=%d, path='%s', flags=0x%x", fd,
		 path ? path : "(empty)", flags);

	if (flags & AT_EMPTY_PATH)
		rc = fstat(fd, &st);
	else
		rc = fstatat(fd, path, &st, AT_SYMLINK_NOFOLLOW);

	if (rc < 0) {
		int err = errno;
		LogDebug(COMPONENT_FSAL, "Error %s (%d)", strerror(err), err);
		errno = err;
		return rc;
	}

	LogDebug(COMPONENT_FSAL, "  st_dev=%lu, st_ino=%lu",
		 (unsigned long)st.st_dev, (unsigned long)st.st_ino);

	fh->handle_data[0] = fs->fsid_type;
	fh->handle_len = 1;

	rc = encode_fsid(fh->handle_data + 1, sizeof_fsid(fs->fsid_type),
			 &fs->fsid, fs->fsid_type);
	if (rc < 0) {
		errno = EINVAL;
		return rc;
	}
	fh->handle_len += rc;

	fh->handle_data[fh->handle_len] = 0xFF; /* synthetic type marker */
	fh->handle_len++;
	fh->handle_data[0] |= HANDLE_TYPE_8;

	if (fh->handle_len + sizeof(st.st_dev) + sizeof(st.st_ino) >
	    VFS_HANDLE_LEN) {
		errno = EOVERFLOW;
		return -1;
	}

	memcpy(fh->handle_data + fh->handle_len, &st.st_dev, sizeof(st.st_dev));
	fh->handle_len += sizeof(st.st_dev);
	memcpy(fh->handle_data + fh->handle_len, &st.st_ino, sizeof(st.st_ino));
	fh->handle_len += sizeof(st.st_ino);

	LogDebug(COMPONENT_FSAL,
		 "Created inode-based handle: dev=%lu, ino=%lu, len=%d",
		 (unsigned long)st.st_dev, (unsigned long)st.st_ino,
		 fh->handle_len);

	return 0;
}

int vfs_open_by_handle(struct fsal_filesystem *fs, vfs_file_handle_t *fh,
		       int openflags, fsal_errors_t *fsal_error)
{
	char full_path[PATH_MAX];
	int fd = -1;

	/*
	 * cursor starts after the flags byte (1) and the encoded fsid
	 * (sizeof_fsid bytes), landing on the synthetic type marker.
	 */
	uint8_t cursor = sizeof_fsid(fs->fsid_type) + 1;

	LogFullDebug(COMPONENT_FSAL, "vfs_open_by_handle: fs=%s openflags=0x%x",
		     fs->path, openflags);
	LogVFSHandle(fh);

	/* Validate handle type field. */
	if ((fh->handle_data[0] & HANDLE_TYPE_MASK) != HANDLE_TYPE_8) {
		LogDebug(COMPONENT_FSAL, "Invalid handle type");
		errno = EINVAL;
		goto out;
	}

	/* Validate synthetic type marker (0xFF). */
	if (fh->handle_data[cursor] != 0xFF) {
		LogDebug(COMPONENT_FSAL,
			 "Not an inode-based handle (marker=0x%02x)",
			 fh->handle_data[cursor]);
		errno = EINVAL;
		goto out;
	}
	cursor++; /* advance past marker */

	/* Validate remaining length before reading dev + ino. */
	if (fh->handle_len < cursor + sizeof(dev_t) + sizeof(ino_t)) {
		LogDebug(COMPONENT_FSAL, "Handle too short (%u)",
			 fh->handle_len);
		errno = EINVAL;
		goto out;
	}

	dev_t target_dev;
	ino_t target_ino;
	if (vfs_inode_handle_decode(fh, &target_dev, &target_ino) < 0) {
		*fsal_error = posix2fsal_error(EINVAL);
		return -EINVAL;
	}

	const char *export_path = op_ctx_export_path(op_ctx);
	if (unlikely(!export_path || !export_path[0])) {
		LogWarn(COMPONENT_FSAL, "Empty export path in op_ctx");
		errno = EINVAL;
		goto out;
	}

	if (vfs_find_path_by_inode(export_path, target_dev, target_ino,
				   full_path) < 0)
		goto out; /* errno already set; logged by callee */

	fd = open(full_path, openflags);
	if (fd < 0)
		LogDebug(COMPONENT_FSAL, "open('%s', 0x%x) failed: %s",
			 full_path, openflags, strerror(errno));

out:
	if (fd < 0) {
		if (errno == ENOENT)
			errno = ESTALE; /* stale handle, not missing file */
		*fsal_error = posix2fsal_error(errno);
		LogDebug(COMPONENT_FSAL,
			 "vfs_open_by_handle failed: %s openflags=0x%x",
			 strerror(errno), openflags);
		return -errno;
	}

	LogFullDebug(COMPONENT_FSAL, "Opened fd %d (%s)", fd, full_path);
	return fd;
}

#else
int vfs_map_name_to_handle_at(int fd, struct fsal_filesystem *fs,
			      const char *path, vfs_file_handle_t *fh,
			      int flags)
{
	struct file_handle *kernel_fh;
	int32_t i32;
	int rc;
	int mnt_id;

	kernel_fh = alloca(sizeof(struct file_handle) + VFS_MAX_HANDLE);

	kernel_fh->handle_bytes = VFS_MAX_HANDLE;

	rc = name_to_handle_at(fd, path, kernel_fh, &mnt_id, flags);

	if (rc < 0) {
		int err = errno;

		LogDebug(COMPONENT_FSAL, "Error %s (%d) bytes = %d",
			 strerror(err), err, (int)kernel_fh->handle_bytes);
		errno = err;
		return rc;
	}

	/* Init flags with fsid type */
	fh->handle_data[0] = fs->fsid_type;
	fh->handle_len = 1;

	/* Pack fsid into wire handle */
	rc = encode_fsid(fh->handle_data + 1, sizeof_fsid(fs->fsid_type),
			 &fs->fsid, fs->fsid_type);

	if (rc < 0) {
		errno = EINVAL;
		return rc;
	}

	fh->handle_len += rc;

	/* Pack handle type into wire handle */
	if (kernel_fh->handle_type <= UINT8_MAX) {
		/* Copy one byte in and advance cursor */
		fh->handle_data[fh->handle_len] = kernel_fh->handle_type;
		fh->handle_len++;
		fh->handle_data[0] |= HANDLE_TYPE_8;
	} else if (kernel_fh->handle_type <= INT16_MAX &&
		   kernel_fh->handle_type >= INT16_MIN) {
		/* Type fits in 16 bits */
		int16_t handle_type_16 = kernel_fh->handle_type;

		memcpy(fh->handle_data + fh->handle_len, &handle_type_16,
		       sizeof(handle_type_16));
		fh->handle_len += sizeof(handle_type_16);
		fh->handle_data[0] |= HANDLE_TYPE_16;
	} else {
		/* Type needs whole 32 bits */
		i32 = kernel_fh->handle_type;
		memcpy(fh->handle_data + fh->handle_len, &i32, sizeof(i32));
		fh->handle_len += sizeof(i32);
		fh->handle_data[0] |= HANDLE_TYPE_32;
	}

	/* Pack opaque handle into wire handle */
	if (fh->handle_len + kernel_fh->handle_bytes > VFS_HANDLE_LEN) {
		/* We just can't fit this handle... */
		errno = EOVERFLOW;
		return -1;
	} else {
		memcpy(fh->handle_data + fh->handle_len, kernel_fh->f_handle,
		       kernel_fh->handle_bytes);
		fh->handle_len += kernel_fh->handle_bytes;
	}

	LogVFSHandle(fh);

	return 0;
}

int vfs_open_by_handle(struct fsal_filesystem *fs, vfs_file_handle_t *fh,
		       int openflags, fsal_errors_t *fsal_error)
{
	struct file_handle *kernel_fh;
	uint8_t handle_cursor = sizeof_fsid(fs->fsid_type) + 1;
	int16_t i16;
	int32_t i32;
	int fd;

	LogFullDebug(COMPONENT_FSAL, "vfs_fs = %s root_fd = %d", fs->path,
		     root_fd(fs));

	LogVFSHandle(fh);

	kernel_fh = alloca(sizeof(struct file_handle) + VFS_MAX_HANDLE);

	switch (fh->handle_data[0] & HANDLE_TYPE_MASK) {
	case 0:
		LogDebug(COMPONENT_FSAL, "Invalid handle type = 0");
		errno = EINVAL;
		fd = -1;
		goto out;
	case HANDLE_TYPE_8:
		kernel_fh->handle_type = fh->handle_data[handle_cursor];
		handle_cursor++;
		break;
	case HANDLE_TYPE_16:
		memcpy(&i16, fh->handle_data + handle_cursor, sizeof(i16));
		handle_cursor += sizeof(i16);
		kernel_fh->handle_type = i16;
		break;
	case HANDLE_TYPE_32:
		memcpy(&i32, fh->handle_data + handle_cursor, sizeof(i32));
		handle_cursor += sizeof(i32);
		kernel_fh->handle_type = i32;
		break;
	}

	kernel_fh->handle_bytes = fh->handle_len - handle_cursor;
	memcpy(kernel_fh->f_handle, fh->handle_data + handle_cursor,
	       kernel_fh->handle_bytes);

	fd = open_by_handle_at(root_fd(fs), kernel_fh, openflags);

out:
	if (fd < 0) {
		fd = -errno;
		if (fd == -ENOENT)
			fd = -ESTALE;
		*fsal_error = posix2fsal_error(-fd);
		LogDebug(COMPONENT_FSAL, "Failed with %s openflags 0x%08x",
			 strerror(-fd), openflags);
	} else {
		LogFullDebug(COMPONENT_FSAL, "Opened fd %d", fd);
	}

	return fd;
}

#endif

int vfs_fd_to_handle(int fd, struct fsal_filesystem *fs, vfs_file_handle_t *fh)
{
	return vfs_map_name_to_handle_at(fd, fs, "", fh, AT_EMPTY_PATH);
}

int vfs_name_to_handle(int atfd, struct fsal_filesystem *fs, const char *name,
		       vfs_file_handle_t *fh)
{
	return vfs_map_name_to_handle_at(atfd, fs, name, fh, 0);
}

int vfs_extract_fsid(vfs_file_handle_t *fh, enum fsid_type *fsid_type,
		     struct fsal_fsid__ *fsid)
{
	LogVFSHandle(fh);

	*fsid_type = (enum fsid_type)fh->handle_data[0] & HANDLE_FSID_MASK;

	if (decode_fsid(fh->handle_data + 1, fh->handle_len - 1, fsid,
			*fsid_type) < 0)
		return ESTALE;
	else
		return 0;
}

int vfs_encode_dummy_handle(vfs_file_handle_t *fh, struct fsal_filesystem *fs)
{
	int rc;

	/* Init flags with fsid type */
	fh->handle_data[0] = fs->fsid_type | HANDLE_DUMMY;
	fh->handle_len = 1;

	/* Pack fsid into wire handle */
	rc = encode_fsid(fh->handle_data + 1, sizeof_fsid(fs->fsid_type),
			 &fs->fsid, fs->fsid_type);

	if (rc < 0) {
		errno = EINVAL;
		return rc;
	}

	fh->handle_len += rc;

	LogVFSHandle(fh);

	return 0;
}

bool vfs_is_dummy_handle(vfs_file_handle_t *fh)
{
	return (fh->handle_data[0] & HANDLE_DUMMY) != 0;
}

bool vfs_valid_handle(struct gsh_buffdesc *desc)
{
	uint8_t handle0;
	int len = 1; /* handle_type */
	bool fsid_type_ok = false;
	bool ok;

	if (desc->addr == NULL) {
		LogDebug(COMPONENT_FSAL, "desc->addr == NULL");
		return false;
	}

	if (desc->len > VFS_HANDLE_LEN) {
		LogDebug(COMPONENT_FSAL, "desc->len %d > VFS_HANDLE_LEN",
			 (int)desc->len);
		return false;
	}

	handle0 = *((uint8_t *)(desc->addr));

	switch ((enum fsid_type)handle0 & HANDLE_FSID_MASK) {
	case FSID_NO_TYPE:
	case FSID_ONE_UINT64:
	case FSID_MAJOR_64:
	case FSID_TWO_UINT64:
	case FSID_TWO_UINT32:
	case FSID_DEVICE:
		fsid_type_ok = true;
		len += sizeof_fsid((enum fsid_type)handle0 & HANDLE_FSID_MASK);
		break;
	}

	if (!fsid_type_ok) {
		LogDebug(COMPONENT_FSAL, "FSID Type %02hhx invalid",
			 (uint8_t)(handle0 & HANDLE_FSID_MASK));
		return false;
	}

	if ((handle0 & HANDLE_DUMMY) != 0) {
		ok = len == desc->len;
		if (!ok) {
			LogDebug(COMPONENT_FSAL,
				 "Len %d != desc->len %d for DUMMY handle", len,
				 (int)desc->len);
		}

		return ok;
	}

	/* min kernel handle size */
	len += sizeof(uint32_t);

	switch (handle0 & HANDLE_TYPE_MASK) {
	case HANDLE_TYPE_8:
		len += sizeof(uint8_t);
		break;
	case HANDLE_TYPE_16:
		len += sizeof(int16_t);
		break;
	case HANDLE_TYPE_32:
		len += sizeof(int32_t);
		break;
	default:
		LogDebug(COMPONENT_FSAL, "Handle Type %02hhx invalid",
			 (uint8_t)(handle0 & HANDLE_TYPE_MASK));
		return false;
	}

	ok = (len + VFS_MIN_HANDLE_SIZE) <= desc->len;
	if (!ok) {
		LogDebug(COMPONENT_FSAL,
			 "Len %d + VFS_MIN_HANDLE_SIZE %d > desc->len %d", len,
			 len + VFS_MIN_HANDLE_SIZE, (int)desc->len);
		return false;
	}
	ok = (len + VFS_MAX_HANDLE) >= desc->len;
	if (!ok) {
		LogDebug(COMPONENT_FSAL,
			 "Len %d + VFS_MAX_HANDLE %d < desc->len %d", len,
			 len + VFS_MAX_HANDLE, (int)desc->len);
	}
	return true;
}

int vfs_re_index(struct fsal_filesystem *fs, struct vfs_fsal_export *exp)
{
	return 0;
}

/** @} */
