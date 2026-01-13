/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
/*
 * This file is derived from
 * http://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git with
 * the following license. As allowed by this license, it is extended to allow
 * this code to link with leancrypto instead of OpenSSL.
 *
 * Note, this license applies ONLY to the sbsigntools implemented by
 * leancrypto as this file is not otherwise used by leancrypto at all.
 * Therefore, licensing of leancrypto in general is unaffected.
 */
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

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "build_bug_on.h"
#include "conv_be_le.h"
#include "image.h"
#include "lc_x509_generator_file_helper.h"
#include "ret_checkers.h"

#define DATA_DIR_CERT_TABLE 4

#define CERT_TABLE_TYPE_PKCS 0x0002 /* PKCS signedData */
#define CERT_TABLE_REVISION 0x0200 /* revision 2 */

/**
 * The PE/COFF headers export struct fields as arrays of chars. So, define
 * a couple of accessor functions that allow fields to be deferenced as their
 * native types, to allow strict aliasing. This also allows for endian-
 * neutral behaviour.
 */
static uint32_t __pehdr_u32(const char field[])
{
	uint8_t *ufield = (uint8_t *)field;
	return ((uint32_t)ufield[3] << 24) + (uint32_t)(ufield[2] << 16) +
	       (uint32_t)(ufield[1] << 8) + (uint32_t)ufield[0];
}

static uint16_t __pehdr_u16(const char field[])
{
	uint8_t *ufield = (uint8_t *)field;
	return (uint16_t)((uint16_t)ufield[1] << 8) + (uint16_t)ufield[0];
}

#define BUILD_ASSERT_OR_ZERO(cond) (sizeof(char[1 - 2 * !(cond)]) - 1)

/* wrappers to ensure type correctness */
#define pehdr_u32(f) __pehdr_u32(f + BUILD_ASSERT_OR_ZERO(sizeof(f) == 4))
#define pehdr_u16(f) __pehdr_u16(f + BUILD_ASSERT_OR_ZERO(sizeof(f) == 2))

/* Machine-specific PE/COFF parse functions. These parse the relevant a.out
 * header for the machine type, and set the following members of struct image:
 *   - aouthdr_size
 *   - file_alignment
 *   - header_size
 *   - data_dir
 *   - checksum
 *
 *  These functions require image->opthdr to be set by the caller.
 */
static int image_pecoff_parse_32(struct image *image)
{
	if (image->opthdr.opt_32->standard.magic[0] != 0x0b ||
	    image->opthdr.opt_32->standard.magic[1] != 0x01) {
		fprintf(stderr, "Invalid a.out machine type\n");
		return -1;
	}

	image->opthdr_min_size = sizeof(*image->opthdr.opt_32) -
				 sizeof(image->opthdr.opt_32->DataDirectory);

	image->file_alignment = pehdr_u32(image->opthdr.opt_32->FileAlignment);
	image->header_size = pehdr_u32(image->opthdr.opt_32->SizeOfHeaders);

	image->data_dir = (void *)image->opthdr.opt_32->DataDirectory;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	image->checksum = (uint32_t *)image->opthdr.opt_32->CheckSum;
#pragma GCC diagnostic pop
	return 0;
}

static int image_pecoff_parse_64(struct image *image)
{
	if (image->opthdr.opt_64->standard.magic[0] != 0x0b ||
	    image->opthdr.opt_64->standard.magic[1] != 0x02) {
		fprintf(stderr, "Invalid a.out machine type\n");
		return -1;
	}

	image->opthdr_min_size = sizeof(*image->opthdr.opt_64) -
				 sizeof(image->opthdr.opt_64->DataDirectory);

	image->file_alignment = pehdr_u32(image->opthdr.opt_64->FileAlignment);
	image->header_size = pehdr_u32(image->opthdr.opt_64->SizeOfHeaders);

	image->data_dir = (void *)image->opthdr.opt_64->DataDirectory;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	image->checksum = (uint32_t *)image->opthdr.opt_64->CheckSum;
#pragma GCC diagnostic pop
	return 0;
}

static size_t align_up(size_t size, size_t align)
{
	return (size + align - 1) & ~(align - 1);
}

static uint16_t csum_update_fold(uint16_t csum, uint16_t x)
{
	uint32_t new = csum + x;
	new = (new >> 16) + (new & 0xffff);
	return (uint16_t)new;
}

static uint16_t csum_bytes(uint16_t checksum, const void *buf, size_t len)
{
	unsigned int i;
	const uint16_t *p = buf;

	for (i = 0; i + sizeof(*p) <= len; i += sizeof(*p)) {
		checksum = csum_update_fold(checksum, *p++);
	}

	/* if length is odd, add the remaining byte */
	if (i < len)
		checksum = csum_update_fold(checksum, *((uint8_t *)p));

	return checksum;
}

static void image_pecoff_update_checksum(struct image *image)
{
	bool is_signed = image->sigsize && image->sigbuf;
	uint32_t checksum;

	/* We carefully only include the signature data in the checksum (and
	 * in the file length) if we're outputting the signature.  Otherwise,
	 * in case of signature removal, the signature data is in the buffer
	 * we read in (as indicated by image->size), but we do *not* want to
	 * checksum it.
	 *
	 * We also skip the 32-bits of checksum data in the PE/COFF header.
	 */
	checksum = csum_bytes(
		0, image->buf,
		(size_t)((uint8_t *)image->checksum - image->buf));
	checksum = csum_bytes((uint16_t)checksum, image->checksum + 1,
			      (size_t)((image->buf + image->data_size) -
				       (uint8_t *)(image->checksum + 1)));

	if (is_signed) {
		checksum = csum_bytes((uint16_t)checksum, image->sigbuf,
				      image->sigsize);
	}

	checksum += image->data_size;

	if (is_signed)
		checksum += image->sigsize;

	*(image->checksum) = le_bswap32(checksum);
}

static int image_pecoff_parse(struct image *image)
{
	const struct cert_table_header *cert_table;
	char nt_sig[] = { 'P', 'E', 0, 0 };
	size_t size = image->size;
	unsigned int cert_table_offset;
	int rc;
	const uint8_t *buf = image->buf;
	uint16_t magic;
	uint32_t addr;

	/* sanity checks */
	if (size < sizeof(*image->doshdr)) {
		fprintf(stderr, "file is too small for DOS header\n");
		return -1;
	}

	image->doshdr = (const struct external_PEI_DOS_hdr *)buf;

	if (image->doshdr->e_magic[0] != 0x4d ||
	    image->doshdr->e_magic[1] != 0x5a) {
		fprintf(stderr, "Invalid DOS header magic\n");
		return -1;
	}

	addr = pehdr_u32(image->doshdr->e_lfanew);
	if (addr >= image->size) {
		fprintf(stderr, "pehdr is beyond end of file [0x%08x]\n", addr);
		return -1;
	}

	if (addr + sizeof(*image->pehdr) > image->size) {
		fprintf(stderr, "File not large enough to contain pehdr\n");
		return -1;
	}

	image->pehdr = (const struct external_PEI_IMAGE_hdr *)(buf + addr);
	if (memcmp(image->pehdr->nt_signature, nt_sig, sizeof(nt_sig))) {
		fprintf(stderr, "Invalid PE header signature\n");
		return -1;
	}

	/* a.out header directly follows PE header */
	image->opthdr.addr = (uint8_t *)(image->pehdr + 1);
	magic = pehdr_u16(image->pehdr->f_magic);

	switch (magic) {
	case IMAGE_FILE_MACHINE_AMD64:
	case IMAGE_FILE_MACHINE_AARCH64:
	case IMAGE_FILE_MACHINE_RISCV64:
		rc = image_pecoff_parse_64(image);
		break;
	case IMAGE_FILE_MACHINE_I386:
	case IMAGE_FILE_MACHINE_THUMB:
		rc = image_pecoff_parse_32(image);
		break;
	default:
		fprintf(stderr, "Invalid PE header magic\n");
		return -1;
	}

	if (rc) {
		fprintf(stderr, "Error parsing a.out header\n");
		return -1;
	}

	/* the optional header has a variable size, as the data directory
	 * has a variable number of entries. Ensure that the we have enough
	 * space to include the security directory entry */
	image->opthdr_size = pehdr_u16(image->pehdr->f_opthdr);
	cert_table_offset =
		sizeof(*image->data_dir) * (DATA_DIR_CERT_TABLE + 1);

	if (image->opthdr_size < image->opthdr_min_size + cert_table_offset) {
		fprintf(stderr,
			"PE opt header too small (%d bytes) to contain "
			"a suitable data directory (need %d bytes)\n",
			image->opthdr_size,
			image->opthdr_min_size + cert_table_offset);
		return -1;
	}

	image->data_dir_sigtable = &image->data_dir[DATA_DIR_CERT_TABLE];

	if (image->size < sizeof(*image->doshdr) + sizeof(*image->pehdr) +
				  image->opthdr_size) {
		fprintf(stderr, "file is too small for a.out header\n");
		return -1;
	}

	image->cert_table_size = image->data_dir_sigtable->size;
	if (image->cert_table_size) {
		cert_table = (const struct cert_table_header *)(buf + image->data_dir_sigtable->addr);
	} else {
		cert_table = NULL;
	}

	image->cert_table = cert_table;

	/* if we have a valid cert table header, populate sigbuf as a shadow
	 * copy of the cert tables */
	if (cert_table && cert_table->revision == CERT_TABLE_REVISION &&
	    cert_table->type == CERT_TABLE_TYPE_PKCS &&
	    cert_table->size < size) {
		image->sigsize = image->data_dir_sigtable->size;
		image->sigbuf = malloc(image->sigsize);
		if (image->sigbuf)
			memcpy(image->sigbuf, cert_table, image->sigsize);
	}

	image->sections = pehdr_u16(image->pehdr->f_nscns);
	image->scnhdr = (const struct external_scnhdr *)(image->opthdr.addr + image->opthdr_size);

	return 0;
}

static int cmp_regions(const void *p1, const void *p2)
{
	const struct region *r1 = p1, *r2 = p2;

	if (r1->data < r2->data)
		return -1;
	if (r1->data > r2->data)
		return 1;
	return 0;
}

static void set_region_from_range(struct region *region, const uint8_t *start,
				  const uint8_t *end)
{
	region->data = start;
	region->size = (size_t)(end - start);
}

static int image_find_regions(struct image *image)
{
	struct region *regions, *r;
	const uint8_t *buf = image->buf;
	int i, gap_warn, ret = 0;
	size_t bytes;

	gap_warn = 0;

	/* now we know where the checksum and cert table data is, we can
	 * construct regions that need to be signed */
	bytes = 0;
	image->n_checksum_regions = 3;
	image->checksum_regions =
		malloc(sizeof(struct region) * image->n_checksum_regions);
	CKNULL(image->checksum_regions, -ENOMEM);

	/* first region: beginning to checksum field */
	regions = image->checksum_regions;
	set_region_from_range(&regions[0], buf, (uint8_t *)image->checksum);
	regions[0].name = "begin->cksum";
	bytes += regions[0].size;

	bytes += sizeof(*image->checksum);

	/* second region: end of checksum to certificate table entry */
	set_region_from_range(&regions[1], (uint8_t *)(image->checksum + 1),
			      (uint8_t *)image->data_dir_sigtable);
	regions[1].name = "cksum->datadir[CERT]";
	bytes += regions[1].size;

	bytes += sizeof(struct data_dir_entry);
	/* third region: end of checksum to end of headers */
	set_region_from_range(&regions[2],
			      (uint8_t *)image->data_dir_sigtable +
				      sizeof(struct data_dir_entry),
			      buf + image->header_size);
	regions[2].name = "datadir[CERT]->headers";
	bytes += regions[2].size;

	/* add COFF sections */
	for (i = 0; i < image->sections; i++) {
		uint32_t file_offset, file_size;
		unsigned int n;

		file_offset = pehdr_u32(image->scnhdr[i].s_scnptr);
		file_size = pehdr_u32(image->scnhdr[i].s_size);

		if (!file_size)
			continue;

		n = image->n_checksum_regions++;
		image->checksum_regions = realloc(
			image->checksum_regions,
			sizeof(struct region) * image->n_checksum_regions);
		CKNULL(image->checksum_regions, -ENOMEM);
		regions = image->checksum_regions;

		regions[n].data = buf + file_offset;
		regions[n].size = file_size;
		regions[n].name = image->scnhdr[i].s_name;
		bytes += regions[n].size;

		if (file_offset + regions[n].size > image->size) {
			fprintf(stderr,
				"warning: file-aligned section %s "
				"extends beyond end of file\n",
				regions[n].name);
		}

		if (regions[n - 1].data + regions[n - 1].size !=
		    regions[n].data) {
			fprintf(stderr, "warning: gap in section table:\n");
			fprintf(stderr, "    %-8s: 0x%08tx - 0x%08tx,\n",
				regions[n - 1].name, regions[n - 1].data - buf,
				regions[n - 1].data + regions[n - 1].size -
					buf);
			fprintf(stderr, "    %-8s: 0x%08tx - 0x%08tx,\n",
				regions[n].name, regions[n].data - buf,
				regions[n].data + regions[n].size - buf);

			gap_warn = 1;
		}
	}

	if (gap_warn)
		fprintf(stderr, "gaps in the section table may result in "
				"different checksums\n");

	qsort(image->checksum_regions, image->n_checksum_regions,
	      sizeof(struct region), cmp_regions);

	if (bytes + image->cert_table_size < image->size) {
		unsigned int n = image->n_checksum_regions++;
		struct region *rsub;

		image->checksum_regions = realloc(
			image->checksum_regions,
			sizeof(struct region) * image->n_checksum_regions);
		CKNULL(image->checksum_regions, -ENOMEM);
		rsub = &image->checksum_regions[n];
		rsub->name = "endjunk";
		rsub->data = image->buf + bytes;
		rsub->size = image->size - bytes - image->cert_table_size;

		//		fprintf(stderr, "warning: data remaining[%zd vs %zd]: gaps "
		//				"between PE/COFF sections?\n",
		//				bytes + image->cert_table_size, image->size);
	} else if (bytes + image->cert_table_size > image->size) {
		fprintf(stderr, "warning: checksum areas are greater than "
				"image size. Invalid section table?\n");
	}

	/* record the size of non-signature data */
	r = &image->checksum_regions[image->n_checksum_regions - 1];
	/*
	 * The new Tianocore multisign does a stricter check of the signatures
	 * in particular, the signature table must start at an aligned offset
	 * fix this by adding bytes to the end of the text section (which must
	 * be included in the hash)
	 */
	image->data_size =
		align_up((size_t)(r->data - image->buf) + r->size, 8);

out:
	return ret;
}

int image_load(const uint8_t *image_buf, size_t image_size, struct image *image)
{
	uint8_t *tmp_buf = NULL;
	int ret;

	memset(image, 0, sizeof(*image));
	image->buf = image_buf;
	image->size = image_size;

reparse:
	CKINT(image_pecoff_parse(image));

	CKINT(image_find_regions(image));

	/* Some images may have incorrectly aligned sections, which get rounded
	 * up to a size that is larger that the image itself (and the buffer
	 * that we've allocated). We would have generated a warning about this,
	 * but we can improve our chances that the verification hash will
	 * succeed by padding the image out to the aligned size, and including
	 * the pad in the signed data.
	 *
	 * In this case, do a realloc, but that may peturb the addresses that
	 * we've calculated during the pecoff parsing, so we need to redo that
	 * too.
	 */
	if (image->data_size > image->size) {
		if (tmp_buf)
			free(tmp_buf);

		tmp_buf = malloc(image->data_size);
		memset(tmp_buf + image->size, 0,
		       image->data_size - image->size);
		memcpy(tmp_buf, image_buf, image_size);
		image->size = image->data_size;
		image->buf = tmp_buf;

		goto reparse;
	}

out:
	return ret;
}

void image_release(struct image *image)
{
	if (!image)
		return;

	if (image->checksum_regions) {
		free(image->checksum_regions);
		image->checksum_regions = NULL;
	}
	if (image->sigbuf) {
		free(image->sigbuf);
		image->sigbuf = NULL;
	}
}

int image_hash(struct image *image, const struct lc_hash *hash,
	       uint8_t digest[], size_t *digestsize)
{
	struct region *region;
	unsigned int i;
	int ret;
	LC_HASH_CTX_ON_STACK(hash_ctx, hash);

	CKINT(lc_hash_init(hash_ctx));

	for (i = 0; i < image->n_checksum_regions; i++) {
		region = &image->checksum_regions[i];
#if 0
		printf("sum region: 0x%04lx -> 0x%04lx [0x%04zx bytes]\n",
		       (uint8_t *)region->data - image->buf,
		       (size_t)((uint8_t *)region->data - image->buf) - 1 +
			       region->size,
		       region->size);

#endif
		lc_hash_update(hash_ctx, region->data, region->size);
	}

	lc_hash_final(hash_ctx, digest);

	*digestsize = lc_hash_digestsize(hash_ctx);

out:
	lc_hash_zero(hash_ctx);
	return ret;
}

int image_add_signature(struct image *image, void *sig, size_t size)
{
	struct cert_table_header *cth;
	size_t tot_size = size + sizeof(*cth);
	size_t aligned_size = align_up(tot_size, 8);
	uint8_t *start;
	int ret = 0;

	if (image->sigbuf) {
		uint8_t *tmp;

		fprintf(stderr,
			"Image was already signed; adding additional signature\n");
		tmp = malloc(image->sigsize + aligned_size);
		CKNULL(tmp, ENOMEM);
		memcpy(tmp, image->sigbuf, image->sigsize);
		free(image->sigbuf);
		image->sigbuf = tmp;
		start = image->sigbuf + image->sigsize;
		image->sigsize += aligned_size;
	} else {
		fprintf(stderr, "Signing Unsigned original image\n");
		start = image->sigbuf = malloc(aligned_size);
		CKNULL(start, ENOMEM);
		image->sigsize = aligned_size;
	}
	cth = (struct cert_table_header *)start;
	start += sizeof(*cth);
	memset(cth, 0, sizeof(*cth));
	cth->size = (uint32_t)tot_size;
	cth->revision = CERT_TABLE_REVISION;
	cth->type = CERT_TABLE_TYPE_PKCS;
	memcpy(start, sig, size);
	if (aligned_size != tot_size)
		memset(start + size, 0, aligned_size - tot_size);

	image->cert_table = cth;

out:
	return ret;
}

int image_get_signature(struct image *image, int signum, uint8_t **buf,
			size_t *size)
{
	struct cert_table_header *header;
	uint8_t *addr = image->sigbuf;
	int i;

	if (!image->sigbuf) {
		fprintf(stderr, "No signature table present\n");
		return -1;
	}

	header = (struct cert_table_header *)addr;
	for (i = 0; i < signum; i++) {
		addr += align_up(header->size, 8);
		header = (struct cert_table_header *)addr;
	}
	if (addr >= (image->sigbuf + image->sigsize))
		return -1;

	*buf = (uint8_t *)(header + 1);
	*size = header->size - sizeof(*header);
	return 0;
}

int image_remove_signature(struct image *image, int signum)
{
	uint8_t *buf;
	size_t size, aligned_size;
	uint8_t *tmp;
	int ret;

	CKINT(image_get_signature(image, signum, &buf, &size));

	buf -= sizeof(struct cert_table_header);
	size += sizeof(struct cert_table_header);
	aligned_size = align_up(size, 8);

	/* is signature at the end? */
	if (buf + aligned_size >= (uint8_t *)image->sigbuf + image->sigsize) {
		/* only one signature? */
		if (image->sigbuf == buf) {
			free(image->sigbuf);
			image->sigbuf = NULL;
			image->sigsize = 0;
			return 0;
		}
	} else {
		/* sig is in the middle ... just copy the rest over it */
		memmove(buf, buf + aligned_size,
			image->sigsize - (size_t)(buf - image->sigbuf) -
				aligned_size);
	}
	image->sigsize -= aligned_size;
	tmp = malloc(image->sigsize);
	CKNULL(tmp, -ENOMEM);
	memcpy(tmp, image->sigbuf, image->sigsize);
	free(image->sigbuf);
	image->sigbuf = tmp;

out:
	return ret;
}

int image_write(struct image *image, const char *filename)
{
	int ret, fd = -1;
	bool is_signed;

	is_signed = image->sigbuf && image->sigsize;

	/* optionally update the image to contain signature data */
	if (is_signed) {
		image->data_dir_sigtable->addr = (uint32_t)image->data_size;
		image->data_dir_sigtable->size = (uint32_t)image->sigsize;
	} else {
		image->data_dir_sigtable->addr = 0;
		image->data_dir_sigtable->size = 0;
	}

	image_pecoff_update_checksum(image);

	fd = open(filename,
		  O_CREAT | O_RDWR | O_TRUNC
#if !(defined(__CYGWIN__) || defined(_WIN32))
			  | O_CLOEXEC
#endif
		  ,
		  0777);
	if (fd < 0) {
		ret = -errno;
		printf("Cannot open file %s\n", filename);
		return ret;
	}

	CKINT(x509_write_data(fd, image->buf, image->data_size));
	if (!is_signed)
		goto out;

	CKINT(x509_write_data(fd, image->sigbuf, image->sigsize));

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

int image_write_detached(struct image *image, int signum, const char *filename)
{
	uint8_t *sig;
	size_t len;
	int ret;

	CKINT(image_get_signature(image, signum, &sig, &len));

	CKINT(write_data(filename, sig, len, lc_pem_flag_nopem));

out:
	return ret;
}
