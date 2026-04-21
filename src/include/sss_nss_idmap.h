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
 * @defgroup sss_nss_idmap sssd pwnam wrapper functions
 *
 * The sssd pwnam wrappers module provides direct idmapping functionality
 * from sssd if the relevant library is available.
 *
 * @{
 */

/**
 * @file sss_nss_idmap.c
 * @brief SSSD idmapping wrappers
 */

#ifndef SSS_NSS_IDMAP_H
#define SSS_NSS_IDMAP_H

#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

int sss_nss_idmap__init(void);

int sss_nss_idmap__getpwnam(const char *name, struct passwd *pwd, char *buffer,
			    size_t buflen, struct passwd **result);

int sss_nss_idmap__getpwuid(uid_t uid, struct passwd *pwd, char *buffer,
			    size_t buflen, struct passwd **result);

int sss_nss_idmap__getgrnam(const char *name, struct group *grp, char *buffer,
			    size_t buflen, struct group **result);

int sss_nss_idmap__getgrgid(gid_t gid, struct group *grp, char *buffer,
			    size_t buflen, struct group **result);

int sss_nss_idmap__getgrouplist(const char *name, gid_t group, gid_t *groups,
				int *ngroups);

#endif /* SSS_NSS_IDMAP_H */
/** @} */
