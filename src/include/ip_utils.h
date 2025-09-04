/* SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 *
 * Copyright: DataDirect Networks, 2025
 * contributeur : Peter Schwenke   pschwenke@ddn.com
 *                Martin Schwenke  mschwenke@ddn.com
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * ---------------------------------------
 */

/**
 * @file ip_utils.h
 * @brief Common tools for IP Address parsing, converting, comparing...
 */

#ifndef __IPUTILS_H
#define __IPUTILS_H

#include "gsh_rpc.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cidr_addr;
typedef struct cidr_addr CIDR;

CIDR *cidr_alloc(void);
CIDR *cidr_dup(const CIDR *);
void cidr_free(CIDR *);
CIDR *cidr_from_str(const char *);
char *cidr_to_str(CIDR *);
CIDR *cidr_from_inaddr(const struct in_addr *);
CIDR *cidr_from_in6addr(const struct in6_addr *);
int cidr_contains_ip(CIDR *, sockaddr_t *);
void cidr_ipaddr_to_chars(CIDR *, unsigned char *);
void cidr_mask_to_chars(CIDR *, unsigned char *);
int cidr_family(CIDR *);
int cidr_proto(CIDR *);
int cidr_version(CIDR *);

#ifdef __cplusplus
}
#endif

#endif /* __IPUTILS_H */
