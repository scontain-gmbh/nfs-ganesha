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
 * @addtogroup pwnam_wrappers
 * @{
 */

/**
 * @file pwnam_wrappers.c
 * @brief pwnam wrappers
 */

#include "pwnam_wrappers.h"
#include "sss_nss_idmap.h"
#include "log.h"

static int getgrouplist_wrapper(const char *user, gid_t group, gid_t *groups,
				int *ngroups)
{
	int res = getgrouplist(user, group, groups, ngroups);
	/* getgrouplist returns -1 for buffer too small */
	if (res == -1)
		errno = ERANGE;
	return res;
}

/*
 * Expected return value for getgrouplist_func is:
 * =>  0 - Success, the user beolngs to N groups
 * <= -1 - Failure (errno can be set to describe the failure)
 *
 * errno:
 * - ERANGE:    Insufficient buffer space supplied
 * - ENOENT:    no user with the given name found
 * - ETIMEDOUT: request timed out
 */
int (*getgrouplist_func)(const char *, __gid_t, __gid_t *,
			 int *) = getgrouplist_wrapper;

int (*getpwnam_r_func)(const char *, struct passwd *, char *, size_t,
		       struct passwd **) = getpwnam_r;

int (*getpwuid_r_func)(uid_t, struct passwd *, char *, size_t,
		       struct passwd **) = getpwuid_r;

int (*getgrnam_r_func)(const char *, struct group *, char *, size_t,
		       struct group **) = getgrnam_r;

int (*getgrgid_r_func)(gid_t, struct group *, char *, size_t,
		       struct group **) = getgrgid_r;

int pwnam_wrappers__set_implementation(pwnam_implementation_t implementation)
{
	switch (implementation) {
	case PWNAM_IMPLEMENTATION__NSSWITCH:
		getgrouplist_func = getgrouplist_wrapper;
		getpwnam_r_func = getpwnam_r;
		getpwuid_r_func = getpwuid_r;
		getgrnam_r_func = getgrnam_r;
		getgrgid_r_func = getgrgid_r;
		LogEvent(COMPONENT_IDMAPPER,
			 "NSSwitch pwnam implementation was loaded.");
		break;
	case PWNAM_IMPLEMENTATION__SSSD:
		if (sss_nss_idmap__init() != 0) {
			LogCrit(COMPONENT_IDMAPPER,
				"Failed to load sss_nss_idmap module.");
			return 1;
		}
		getgrouplist_func = sss_nss_idmap__getgrouplist;
		getpwnam_r_func = sss_nss_idmap__getpwnam;
		getpwuid_r_func = sss_nss_idmap__getpwuid;
		getgrnam_r_func = sss_nss_idmap__getgrnam;
		getgrgid_r_func = sss_nss_idmap__getgrgid;
		LogEvent(COMPONENT_IDMAPPER,
			 "SSSD pwnam implementation was loaded.");
		break;
	default:
		LogFatal(COMPONENT_IDMAPPER,
			 "Unsupported pwnam implementation");
	}

	return 0;
}

int pwnam_wrappers__getgrouplist(const char *user, gid_t group, gid_t *groups,
				 int *ngroups)
{
	return getgrouplist_func(user, group, groups, ngroups);
}

int pwnam_wrappers__getpwnam_r(const char *name, struct passwd *pwd, char *buf,
			       size_t buflen, struct passwd **result)
{
	return getpwnam_r_func(name, pwd, buf, buflen, result);
}

int pwnam_wrappers__getpwuid_r(uid_t uid, struct passwd *pwd, char *buf,
			       size_t buflen, struct passwd **result)
{
	return getpwuid_r_func(uid, pwd, buf, buflen, result);
}

int pwnam_wrappers__getgrnam_r(const char *name, struct group *grp, char *buf,
			       size_t buflen, struct group **result)
{
	return getgrnam_r_func(name, grp, buf, buflen, result);
}

int pwnam_wrappers__getgrgid_r(gid_t gid, struct group *grp, char *buf,
			       size_t buflen, struct group **result)
{
	return getgrgid_r_func(gid, grp, buf, buflen, result);
}
