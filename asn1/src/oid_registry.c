/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
/*
 * This code is derived in parts from the Linux kernel
 * License: SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
/*
 * Red Hat granted the following additional license to the leancrypto project:
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "asn1.h"
#include "ext_headers_internal.h"
#include "oid_registry.h"
#include "oid_registry_data.c"

/**
 * look_up_OID - Find an OID registration for the specified data
 * @data: Binary representation of the OID
 * @datasize: Size of the binary representation
 */
enum OID lc_look_up_OID(const uint8_t *data, size_t datasize)
{
	enum OID oid;
	size_t len, hash;
	unsigned int i, j, k;
	unsigned char xhash;

	/* Hash the OID data */
	hash = datasize - 1;

	for (i = 0; i < datasize; i++)
		hash += data[i] * 33;
	hash = (hash >> 24) ^ (hash >> 16) ^ (hash >> 8) ^ hash;
	hash &= 0xff;

	/* Binary search the OID registry.  OIDs are stored in ascending order
	 * of hash value then ascending order of size and then in ascending
	 * order of reverse value.
	 */
	i = 0;
	k = OID__NR;
	while (i < k) {
		j = (i + k) / 2;

		xhash = oid_search_table[j].hash;
		if (xhash > hash) {
			k = j;
			continue;
		}
		if (xhash < hash) {
			i = j + 1;
			continue;
		}

		oid = oid_search_table[j].oid;
		len = oid_index[oid + 1] - oid_index[oid];
		if (len > datasize) {
			k = j;
			continue;
		}
		if (len < datasize) {
			i = j + 1;
			continue;
		}

		/* Variation is most likely to be at the tail end of the
		 * OID, so do the comparison in reverse.
		 */
		while (len > 0) {
			unsigned char a = oid_data[oid_index[oid] + --len];
			unsigned char b = data[len];
			if (a > b) {
				k = j;
				goto next;
			}
			if (a < b) {
				i = j + 1;
				goto next;
			}
		}
		return oid;
	next:;
	}

	return OID__NR;
}

/**
 * parse_OID - Parse an OID from a bytestream
 * @data: Binary representation of the header + OID
 * @datasize: Size of the binary representation
 * @oid: Pointer to oid to return result
 *
 * Parse an OID from a bytestream that holds the OID in the format
 * ASN1_OID | length | oid. The length indicator must equal to datasize - 2.
 * -EBADMSG is returned if the bytestream is too short.
 */
int lc_parse_OID(const uint8_t *data, size_t datasize, enum OID *oid)
{
	/* we need 2 bytes of header and at least 1 byte for oid */
	if (datasize < 3 || data[0] != ASN1_OID || data[1] != datasize - 2)
		return -EBADMSG;

	*oid = lc_look_up_OID(data + 2, datasize - 2);
	return 0;
}

/*
 * sprint_OID - Print an Object Identifier into a buffer
 * @data: The encoded OID to print
 * @datasize: The size of the encoded OID
 * @buffer: The buffer to render into
 * @bufsize: The size of the buffer
 *
 * The OID is rendered into the buffer in "a.b.c.d" format and the number of
 * bytes is returned.  -EBADMSG is returned if the data could not be interpreted
 * and -ENOBUFS if the buffer was too small.
 */
int lc_sprint_oid(const uint8_t *data, size_t datasize, char *buffer,
		  size_t bufsize)
{
	const uint8_t *end = data + datasize;
	unsigned long num;
	unsigned char n;
	int count;
	int ret;

	if (data >= end || bufsize > INT_MAX)
		goto bad;

	n = *data++;
	ret = count = snprintf(buffer, bufsize, "%u.%u", n / 40, n % 40);
	if (count >= (int)bufsize)
		return -ENOBUFS;
	buffer += count;
	bufsize -= (size_t)count;

	while (data < end) {
		n = *data++;
		if (!(n & 0x80)) {
			num = n;
		} else {
			num = n & 0x7f;
			do {
				if (data >= end)
					goto bad;
				n = *data++;
				num <<= 7;
				num |= n & 0x7f;
			} while (n & 0x80);
		}
		ret += count = snprintf(buffer, bufsize, ".%lu", num);
		if (count >= (int)bufsize)
			return -ENOBUFS;
		buffer += count;
		bufsize -= (size_t)count;
	}

	return ret;

bad:
	snprintf(buffer, bufsize, "(bad)");
	return -EBADMSG;
}

/**
 * sprint_OID - Print an Object Identifier into a buffer
 * @oid: The OID to print
 * @buffer: The buffer to render into
 * @bufsize: The size of the buffer
 *
 * The OID is rendered into the buffer in "a.b.c.d" format and the number of
 * bytes is returned.
 */
int lc_sprint_OID(enum OID oid, char *buffer, size_t bufsize)
{
	if (oid >= OID__NR)
		return -EFAULT;

	return lc_sprint_oid(oid_data + oid_index[oid],
			     oid_index[oid + 1] - oid_index[oid], buffer,
			     bufsize);
}

/**
 * @brief Obtain reference to binary representation of OID
 *
 * @param [in] oid OID to convert to binary representation
 * @param [out] data pointer to the binary OID data
 * @param [out] datalen Length of the binary OID data buffer
 */
int lc_OID_to_data(enum OID oid, const uint8_t **data, size_t *datalen)
{
	if (oid >= OID__NR)
		return -EFAULT;

	*data = oid_data + oid_index[oid];
	*datalen = oid_index[oid + 1] - oid_index[oid];
	return 0;
}
