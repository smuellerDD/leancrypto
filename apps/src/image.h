/*
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the OpenSSL
 * library under certain conditions as described in each individual source file,
 * and distribute linked combinations including the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 */
#ifndef IMAGE_H
#define IMAGE_H

#include <stdint.h>

#define DO_NOT_DEFINE_LINENO

#include "coff/external.h"
#include "coff/pe.h"
#include "lc_hash.h"

struct region {
	const uint8_t *data;
	size_t size;
	const char *name;
};

struct image {
	const uint8_t *buf;
	size_t size;

	/* size of the image, without signature */
	size_t data_size;

	/* Pointers to interesting parts of the image */
	uint32_t *checksum;
	const struct external_PEI_DOS_hdr *doshdr;
	const struct external_PEI_IMAGE_hdr *pehdr;
	union {
		PEPAOUTHDR *opt_64;
		PEAOUTHDR *opt_32;
		const uint8_t *addr;
	} opthdr;
	/* size of a minimal opthdr for this machine, without data
	 * directories */
	unsigned int opthdr_min_size;
	/* size of the opthdr as specified by the image */
	unsigned int opthdr_size;
	struct data_dir_entry *data_dir;
	struct data_dir_entry *data_dir_sigtable;
	const struct external_scnhdr *scnhdr;
	int sections;

	const void *cert_table;
	unsigned int cert_table_size;

	/* We cache a few values from the aout header, so we don't have to
	 * keep checking whether to use the 32- or 64-bit version */
	uint32_t file_alignment;
	uint32_t header_size;

	/* Regions that are included in the image hash: populated
	 * during image parsing, then used during the hash process.
	 */
	struct region *checksum_regions;
	unsigned int n_checksum_regions;

	/* Generated signature */
	uint8_t *sigbuf;
	size_t sigsize;
};

struct data_dir_entry {
	uint32_t addr;
	uint32_t size;
} __attribute__((packed));

struct cert_table_header {
	uint32_t size;
	uint16_t revision;
	uint16_t type;
} __attribute__((packed));

int image_load(const uint8_t *image_buf, size_t image_size,
	       struct image *image);

int image_hash(struct image *image, const struct lc_hash *hash,
	       uint8_t digest[], size_t *digestsize);
int image_add_signature(struct image *, void *sig, size_t size);
int image_get_signature(struct image *image, unsigned int signum, uint8_t **buf,
			size_t *size);
int image_remove_signature(struct image *image, unsigned int signum);
int image_write(struct image *image, const char *filename);
int image_write_detached(struct image *image, unsigned int signum,
			 const char *filename);
void image_release(struct image *image);

#endif /* IMAGE_H */
