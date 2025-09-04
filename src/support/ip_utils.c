// SPDX-License-Identifier: LGPL-3.0-or-later */
/*
 * Copyright: DataDirect Networks, 2025
 * Copyright (c) Matthew D. Fuller <fullermd@over-yonder.net> 2005, 2006
 *
 * contributeur : Peter Schwenke   pschwenke@ddn.com
 *                Martin Schwenke  mschwenke@ddn.com
 *
 * We thank Matthew D. Fuller for providing the original libcidr used
 * by the NFS Ganesha project for a long time.  The cidr_* functions herein
 * mostly match the signature and functionality of the libcidr versions whilst
 * being completely new implementations.
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
 * @file ip_utils.c
 * @brief Tools for IP Addresses and CIDRs - parsing, converting, comparing...
 */

#include <errno.h>
#include <sys/un.h>

#include "ip_utils.h"

struct cidr_addr {
	sockaddr_t ip_addr;
	u_int16_t mask;
};

/**
 * @brief Allocate a CIDR struct
 *
 * @return CIDR struct
*/
CIDR *cidr_alloc(void)
{
	return gsh_calloc(1, sizeof(CIDR));
}

/**
 * @brief Free a CIDR structure
 *
 * @in cidr      CIDR structure
 */
void cidr_free(CIDR *cidr)
{
	gsh_free(cidr);
}

/**
 * @brief Create a CIDR structure from an IP addr/mask string
 *
 * @in addr      IP Address/Mask string e.g. 192.168.10.0/24
 *                                           fe80::5a4d:7416:a595:bd6f/64
 *
 * @return CIDR structure, NULL on parse failure with errno=EINVAL
 */
CIDR *cidr_from_str(const char *addr)
{
	CIDR *cidr;
	char addr_str[SOCK_NAME_MAX];
	char *slash = NULL;
	char *mask_str = NULL;
	int ret;

	strcpy(addr_str, addr);

	slash = strchr(addr_str, '/');

	if (slash != NULL) {
		*slash = '\0';
		mask_str = slash + 1;
	}

	cidr = cidr_alloc();
	ret = ip_str_to_sockaddr(addr_str, &(cidr->ip_addr));
	if (ret) {
		cidr_free(cidr);
		errno = EINVAL;
		return NULL;
	}

	if (mask_str) {
		unsigned long mask;
		char *end = NULL;

		mask = strtoul(mask_str, &end, 10);

		if (mask_str == end || *end != '\0') {
			cidr_free(cidr);
			errno = EINVAL;
			return NULL;
		}

		switch (cidr->ip_addr.ss_family) {
		case AF_INET:
			if (mask > 32) {
				cidr_free(cidr);
				errno = EINVAL;
				return NULL;
			}
			break;
		case AF_INET6:
			if (mask > 128) {
				cidr_free(cidr);
				errno = EINVAL;
				return NULL;
			}
			break;
		}
		cidr->mask = mask;
	} else {
		switch (cidr->ip_addr.ss_family) {
		case AF_INET:
			cidr->mask = 32;
			break;
		case AF_INET6:
			cidr->mask = 128;
			break;
		}
	}

	return cidr;
}

/**
 * @brief Convert a CIDR structure to a string
 *
 * @in addr      IP Address string
 *
 * @return CIDR structure
 */
char *cidr_to_str(CIDR *cidr)
{
	char *cidr_string;

	cidr_string = gsh_calloc(SOCK_NAME_MAX, sizeof(char));

	struct display_buffer dspbuf = { SOCK_NAME_MAX * sizeof(char),
					 cidr_string, cidr_string };

	display_sockip(&dspbuf, &cidr->ip_addr);
	display_printf(&dspbuf, "/%d", cidr->mask);
	return cidr_string;
}

/**
 * @brief See if an IP address is within a CIDR
 *
 * @in cidr      CIDR containing mask and IP address
 * @in ipaddr    IP Address
 *
 * @return 0 on match, -1 if not matched - errno is set to EINVAL if invalid
 */
int cidr_contains_ip(CIDR *cidr, sockaddr_t *ipaddr)
{
	int mask = cidr->mask;

	errno = 0;
	if (cidr->ip_addr.ss_family != ipaddr->ss_family) {
		errno = EINVAL;
		return -1;
	}

	if (cidr->ip_addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *cidr_v6 =
			(struct sockaddr_in6 *)&cidr->ip_addr;
		struct sockaddr_in6 *ipaddr_v6 = (struct sockaddr_in6 *)ipaddr;
		uint8_t mask_bytes = mask / 8;
		uint8_t mask_bits = mask % 8;
		uint8_t cidr_byte;
		uint8_t ipaddr_byte;

		for (int i = 0; i < mask_bytes; i++) {
			if (cidr_v6->sin6_addr.s6_addr[i] !=
			    ipaddr_v6->sin6_addr.s6_addr[i]) {
				errno = 0;
				return -1;
			}
		}

		if (mask_bits == 0) {
			return 0;
		}

		cidr_byte = cidr_v6->sin6_addr.s6_addr[mask_bytes];
		ipaddr_byte = ipaddr_v6->sin6_addr.s6_addr[mask_bytes];
		if ((cidr_byte >> (8 - mask_bits)) ==
		    (ipaddr_byte >> (8 - mask_bits))) {
			return 0;
		} else {
			errno = 0;
			return -1;
		}
	} else if (cidr->ip_addr.ss_family == AF_INET) {
		struct sockaddr_in *cidr_v4 =
			(struct sockaddr_in *)&cidr->ip_addr;
		struct sockaddr_in *ipaddr_v4 = (struct sockaddr_in *)ipaddr;
		int cidr_addr = ntohl(cidr_v4->sin_addr.s_addr);
		int ipaddr_addr = ntohl(ipaddr_v4->sin_addr.s_addr);

		int b = cidr_addr >> (32 - mask);
		int s = ipaddr_addr >> (32 - mask);

		if (b == s) {
			return 0;
		}
	}

	errno = 0;
	return -1;
}

/**
 * @brief Create a CIDR struct from an in_addr
 *
 * @param[in] addr IPv4 Address
 *
 * @return CIDR structure
*/
CIDR *cidr_from_inaddr(const struct in_addr *addr)
{
	CIDR *cidr;

	cidr = cidr_alloc();
	memcpy(&((struct sockaddr_in *)&cidr->ip_addr)->sin_addr.s_addr, addr,
	       sizeof(sockaddr_t));
	cidr->ip_addr.ss_family = AF_INET;
	cidr->mask = 32;

	return cidr;
}

/**
 * @brief Create a CIDR struct from an in6_addr
 *
 * @param[in] addr IPv6 Address
 *
 * @return CIDR structure
 */
CIDR *cidr_from_in6addr(const struct in6_addr *addr)
{
	CIDR *cidr;

	cidr = cidr_alloc();
	cidr->ip_addr.ss_family = AF_INET6;

	memcpy(&((struct sockaddr_in6 *)&cidr->ip_addr)->sin6_addr.s6_addr,
	       addr, sizeof(struct in6_addr));

	cidr->mask = 128;
	return cidr;
}

/**
 * @brief Extra the IP address from a CIDR as an array of 16 bytes
 *
 * @param[in]  cidr    A CIDR
 * @param[out] chars   A 16 byte array should be passed here
 *
 * NFS Ganesha previously used libcidr which stored the address
 * as a series of bytes [192 168 10 0] etc.  There is one
 * spot in the Ganesha code that grabs a byte from an array like
 * that. So this function provides that array for now.
 */
void cidr_ipaddr_to_chars(CIDR *cidr, unsigned char *chars)
{
	struct sockaddr_in6 *ip_v6;
	struct sockaddr_in *ip_v4;
	unsigned char *saddr_bytes;

	memset(chars, 0, 16);
	switch (cidr->ip_addr.ss_family) {
	case AF_INET:
		ip_v4 = (struct sockaddr_in *)&cidr->ip_addr;
		saddr_bytes = (unsigned char *)&ip_v4->sin_addr.s_addr;

		for (int i = 12, z = 0; i < 16; i++, z++) {
			chars[i] = saddr_bytes[z];
		}

		break;
	case AF_INET6:
		ip_v6 = (struct sockaddr_in6 *)&cidr->ip_addr;

		for (int i = 0; i < 16; i++) {
			chars[i] = ip_v6->sin6_addr.s6_addr[i];
		}

		break;
	}
}

/**
 * @brief Extra the numeric mask from a CIDR as an array of 16 bytes
 *
 * @param[in]  cidr    A CIDR
 * @param[out] chars   A 16 byte array should be passed here
 *
 * NFS Ganesha previously used libcidr which stored the mask
 * as a series of bytes [255 255 255] etc.  There is one
 * spot in the Ganesha code that grabs a byte from an array like
 * that. So this function provides that array for now.
 */
void cidr_mask_to_chars(CIDR *cidr, unsigned char *chars)
{
	int mask_bytes = cidr->mask / 8;
	int mask_bits = cidr->mask % 8;
	int i = 0;
	int z;

	memset(chars, 0, 16);
	switch (cidr->ip_addr.ss_family) {
	case AF_INET:
		for (i = 0; i < 12; i++) {
			chars[i] = 0xff;
		}

		for (i = 12, z = 0; z < mask_bytes; i++, z++) {
			chars[i] = 0xff;
		}
		chars[i] = 0xff << (8 - mask_bits);
		break;
	case AF_INET6:
		for (i = 0; i < mask_bytes; i++) {
			chars[i] = 0xff;
		}
		chars[i] = 0xff << (8 - mask_bits);

		break;
	}
}

/**
 * @brief Return the IP family (ss_family) of the CIDR
 *
 * @param[in]  cidr    A CIDR
 *
 */
int cidr_family(CIDR *cidr)
{
	return cidr->ip_addr.ss_family;
}

/**
 * @brief Return the protocol type as from libcidr
 *
 * @param[in]  cidr    A CIDR
 *
 * NFS Ganesha previously used libcidr which stored the
 * protocol as 1 for IPv4 and IPv6.  We store the more useful
 * ss_family.  One spot in the export_mgr sends this on DBUS
 * with some other (not useful) info.  This is provided, for
 * now, in case someone is parsing the ExportMgr/DisplayExport
 * output or something.
 */
int cidr_proto(CIDR *cidr)
{
	return (cidr->ip_addr.ss_family == AF_INET ? 1 : 2);
}

/**
 * @brief Return the CIDR version
 *
 * @param[in]  cidr    A CIDR
 *
 * A hang over from the libcidr days.  This field can probably disappear
 * down the track. One spot in the export_mgr sends this on DBUS.
 * This is provided, for now, in case someone is parsing the
 * ExportMgr/DisplayExport output or something.
 *
 * @return 0 was returned previously, let's return 1 for kicks.
 */
int cidr_version(CIDR *cidr)
{
	return 1;
}
