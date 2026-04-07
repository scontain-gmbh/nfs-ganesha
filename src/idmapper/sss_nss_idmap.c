// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Lior Suliman   liorsu@google.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @addtogroup sss_nss_idmap
 * @{
 */

/**
 * @file    sss_nss_idmap.c
 * @brief   SSSD idmapping wrappers
 */

#include "sss_nss_idmap.h"

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>

#include "log.h"
#include "log_common.h"
#include "sss_nss_idmap.h"
#include "gsh_config.h"

typedef int (*sss_nss_getpwnam_timeout_t)(const char *name, struct passwd *pwd,
					  char *buffer, size_t buflen,
					  struct passwd **result,
					  uint32_t flags, unsigned int timeout);
typedef int (*sss_nss_getpwuid_timeout_t)(uid_t uid, struct passwd *pwd,
					  char *buffer, size_t buflen,
					  struct passwd **result,
					  uint32_t flags, unsigned int timeout);
typedef int (*sss_nss_getgrnam_timeout_t)(const char *name, struct group *grp,
					  char *buffer, size_t buflen,
					  struct group **result, uint32_t flags,
					  unsigned int timeout);
typedef int (*sss_nss_getgrgid_timeout_t)(gid_t gid, struct group *grp,
					  char *buffer, size_t buflen,
					  struct group **result, uint32_t flags,
					  unsigned int timeout);
typedef int (*sss_nss_getgrouplist_timeout_t)(const char *name, gid_t group,
					      gid_t *groups, int *ngroups,
					      uint32_t flags,
					      unsigned int timeout);

static bool is_inited;
static void *handle;
static int32_t sssd_flags;
static unsigned int sssd_timeout;
sss_nss_getpwnam_timeout_t sss_nss_getpwnam_timeout;
sss_nss_getpwuid_timeout_t sss_nss_getpwuid_timeout;
sss_nss_getgrnam_timeout_t sss_nss_getgrnam_timeout;
sss_nss_getgrgid_timeout_t sss_nss_getgrgid_timeout;
sss_nss_getgrouplist_timeout_t sss_nss_getgrouplist_timeout;

/**
 * Flags to control the behavior and the results for sss_*_ex() calls
 */

#define SSS_NSS_EX_FLAG_NO_FLAGS 0

/** Always request data from the server side, client must be privileged to do
 *  so, see nss_trusted_users option in man sssd.conf for details.
 *  This flag cannot be used together with SSS_NSS_EX_FLAG_INVALIDATE_CACHE */
#define SSS_NSS_EX_FLAG_NO_CACHE (1 << 0)

/** Invalidate the data in the caches, client must be privileged to do
 *  so, see nss_trusted_users option in man sssd.conf for details.
 *  This flag cannot be used together with SSS_NSS_EX_FLAG_NO_CACHE */
#define SSS_NSS_EX_FLAG_INVALIDATE_CACHE (1 << 1)

int sss_nss_idmap__getpwnam(const char *name, struct passwd *pwd, char *buffer,
			    size_t buflen, struct passwd **result)
{
	if (!is_inited)
		LogFatal(
			COMPONENT_IDMAPPER,
			"Attempted to call sss_nss_idmap__getpwnam without successful init");
	return sss_nss_getpwnam_timeout(name, pwd, buffer, buflen, result,
					sssd_flags, sssd_timeout);
}

int sss_nss_idmap__getpwuid(uid_t uid, struct passwd *pwd, char *buffer,
			    size_t buflen, struct passwd **result)
{
	if (!is_inited)
		LogFatal(
			COMPONENT_IDMAPPER,
			"Attempted to call sss_nss_idmap__getpwuid without successful init");
	return sss_nss_getpwuid_timeout(uid, pwd, buffer, buflen, result,
					sssd_flags, sssd_timeout);
}

int sss_nss_idmap__getgrnam(const char *name, struct group *grp, char *buffer,
			    size_t buflen, struct group **result)
{
	if (!is_inited)
		LogFatal(
			COMPONENT_IDMAPPER,
			"Attempted to call sss_nss_idmap__getgrnam without successful init");
	return sss_nss_getgrnam_timeout(name, grp, buffer, buflen, result,
					sssd_flags, sssd_timeout);
}

int sss_nss_idmap__getgrgid(gid_t gid, struct group *grp, char *buffer,
			    size_t buflen, struct group **result)
{
	if (!is_inited)
		LogFatal(
			COMPONENT_IDMAPPER,
			"Attempted to call sss_nss_idmap__getgrgid without successful init");
	return sss_nss_getgrgid_timeout(gid, grp, buffer, buflen, result,
					sssd_flags, sssd_timeout);
}

int sss_nss_idmap__getgrouplist(const char *name, gid_t group, gid_t *groups,
				int *ngroups)
{
	if (!is_inited)
		LogFatal(COMPONENT_IDMAPPER,
			 "Attempted to call sss_nss_idmap__getgrouplist without successful "
			 "init");
	int res = sss_nss_getgrouplist_timeout(name, group, groups, ngroups,
					       sssd_flags, sssd_timeout);
	if (res != 0) {
		errno = res;
		return -1;
	} else
		return *ngroups;
}

int sss_nss_idmap__init(void)
{
	const bool skip_cache = nfs_param.directory_services_param
					.sssd_implementation_skip_cache;
	sssd_flags = skip_cache ? SSS_NSS_EX_FLAG_NO_CACHE
				: SSS_NSS_EX_FLAG_NO_FLAGS;
	sssd_timeout =
		nfs_param.directory_services_param.sssd_implementation_timeout *
		1000;
	LogInfo(COMPONENT_IDMAPPER,
		"SSSD Implementation configuration: timeout: %d ms, skip cache: %d",
		sssd_timeout, skip_cache);

	if (is_inited)
		return 0;

	if (handle != NULL) {
		// A previous init attempt was failed
		return 1;
	}

	handle = dlopen("libsss_nss_idmap.so.0", RTLD_LAZY);
	if (handle == NULL) {
		LogCrit(COMPONENT_IDMAPPER,
			"Failed to dynamically load libsss_nss_idmap.so, error: %s",
			dlerror());
		return 1;
	}

	sss_nss_getpwnam_timeout =
		(sss_nss_getpwnam_timeout_t)dlsym(handle,
						  "sss_nss_getpwnam_timeout");
	if (sss_nss_getpwnam_timeout == NULL) {
		LogCrit(COMPONENT_IDMAPPER,
			"Failed to dlsym function: sss_nss_getpwnam_timeout, error: %s",
			dlerror());
		return 1;
	}

	sss_nss_getpwuid_timeout =
		(sss_nss_getpwuid_timeout_t)dlsym(handle,
						  "sss_nss_getpwuid_timeout");
	if (sss_nss_getpwuid_timeout == NULL) {
		LogCrit(COMPONENT_IDMAPPER,
			"Failed to dlsym function: sss_nss_getpwuid_timeout, error: %s",
			dlerror());
		return 1;
	}

	sss_nss_getgrnam_timeout =
		(sss_nss_getgrnam_timeout_t)dlsym(handle,
						  "sss_nss_getgrnam_timeout");
	if (sss_nss_getgrnam_timeout == NULL) {
		LogCrit(COMPONENT_IDMAPPER,
			"Failed to dlsym function: sss_nss_getgrnam_timeout, error: %s",
			dlerror());
		return 1;
	}

	sss_nss_getgrgid_timeout =
		(sss_nss_getgrgid_timeout_t)dlsym(handle,
						  "sss_nss_getgrgid_timeout");
	if (sss_nss_getgrgid_timeout == NULL) {
		LogCrit(COMPONENT_IDMAPPER,
			"Failed to dlsym function: sss_nss_getgrgid_timeout, error: %s",
			dlerror());
		return 1;
	}

	sss_nss_getgrouplist_timeout = (sss_nss_getgrouplist_timeout_t)dlsym(
		handle, "sss_nss_getgrouplist_timeout");
	if (sss_nss_getgrouplist_timeout == NULL) {
		LogCrit(COMPONENT_IDMAPPER,
			"Failed to dlsym function: sss_nss_getgrouplist_timeout, error: %s",
			dlerror());
		return 1;
	}

	is_inited = true;
	return 0;
}

/**
 * @brief Return user information based on the user name
 *
 * @param[in]  name       same as for getpwnam_r(3)
 * @param[in]  pwd        same as for getpwnam_r(3)
 * @param[in]  buffer     same as for getpwnam_r(3)
 * @param[in]  buflen     same as for getpwnam_r(3)
 * @param[out] result     same as for getpwnam_r(3)
 * @param[in]  flags      flags to control the behavior and the results of the
 *                        call
 * @param[in]  timeout    timeout in milliseconds
 *
 * @return
 *  - 0:
 *  - ENOENT:    no user with the given name found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */

/**
 * @brief Return user information based on the user uid
 *
 * @param[in]  uid        same as for getpwuid_r(3)
 * @param[in]  pwd        same as for getpwuid_r(3)
 * @param[in]  buffer     same as for getpwuid_r(3)
 * @param[in]  buflen     same as for getpwuid_r(3)
 * @param[out] result     same as for getpwuid_r(3)
 * @param[in]  flags      flags to control the behavior and the results of the
 *                        call
 * @param[in]  timeout    timeout in milliseconds
 *
 * @return
 *  - 0:
 *  - ENOENT:    no user with the given uid found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */

/**
 * @brief Return group information based on the group name
 *
 * @param[in]  name       same as for getgrnam_r(3)
 * @param[in]  pwd        same as for getgrnam_r(3)
 * @param[in]  buffer     same as for getgrnam_r(3)
 * @param[in]  buflen     same as for getgrnam_r(3)
 * @param[out] result     same as for getgrnam_r(3)
 * @param[in]  flags      flags to control the behavior and the results of the
 *                        call
 * @param[in]  timeout    timeout in milliseconds
 *
 * @return
 *  - 0:
 *  - ENOENT:    no group with the given name found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */

/**
 * @brief Return group information based on the group gid
 *
 * @param[in]  gid        same as for getgrgid_r(3)
 * @param[in]  pwd        same as for getgrgid_r(3)
 * @param[in]  buffer     same as for getgrgid_r(3)
 * @param[in]  buflen     same as for getgrgid_r(3)
 * @param[out] result     same as for getgrgid_r(3)
 * @param[in]  flags      flags to control the behavior and the results of the
 *                        call
 * @param[in]  timeout    timeout in milliseconds
 *
 * @return
 *  - 0:
 *  - ENOENT:    no group with the given gid found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */

/**
 * @brief Return a list of groups to which a user belongs
 *
 * @param[in]      name       name of the user
 * @param[in]      group      same as second argument of getgrouplist(3)
 * @param[in]      groups     array of gid_t of size ngroups, will be filled
 *                            with GIDs of groups the user belongs to
 * @param[in,out]  ngroups    size of the groups array on input. On output it
 *                            will contain the actual number of groups the
 *                            user belongs to. With a return value of 0 the
 *                            groups array was large enough to hold all group.
 *                            With a return value of ERANGE the array was not
 *                            large enough and ngroups will have the needed
 *                            size.
 * @param[in]  flags          flags to control the behavior and the results of
 *                            the call
 * @param[in]  timeout        timeout in milliseconds
 *
 * @return
 *  - 0:         success
 *  - ENOENT:    no user with the given name found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */

/** @} */
