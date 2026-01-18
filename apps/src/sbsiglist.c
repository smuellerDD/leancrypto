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
 * This implementation is intended to provide a drop-in replacement for the
 * sbsign tool from
 * http://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git.
 *
 * The file is derived from this code with the following license:
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
#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <getopt.h>

#include "efivars.h"

#include "helper.h"
#include "lc_memory_support.h"
#include "lc_status.h"
#include "lc_uuid.h"
#include "lc_x509_generator_file_helper.h"
#include "ret_checkers.h"

static const char *toolname = "sbsiglist";

static struct option options[] = {
	{ "output", required_argument, NULL, 'o' },
	{ "type", required_argument, NULL, 't' },
	{ "owner", required_argument, NULL, 'w' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 },
};

struct cert_type {
	const char	*name;
	const EFI_GUID	guid;
	unsigned int	sigsize;
};

struct cert_type cert_types[] = {
	{ "x509",   EFI_CERT_X509_GUID,   0 },
	{ "sha256", EFI_CERT_SHA256_GUID, 32 },
};

struct siglist_context {
	int			verbose;

	const char		*infilename;
	char		*outfilename;
	const struct cert_type	*type;
	EFI_GUID		owner;

	uint8_t			*data;
	size_t			data_len;

	EFI_SIGNATURE_LIST	*siglist;
};


static void usage(void)
{
	unsigned int i;

	printf("Usage: %s [options] --owner <guid> --type <type> <sig-file>\n"
		"Create an EFI_SIGNATURE_LIST from a signature file\n"
		"Options:\n"
		"\t--owner <guid>   Signature owner GUID\n"
		"\t--type <type>    Signature type. One of:\n",
		toolname);

	for (i = 0; i < ARRAY_SIZE(cert_types); i++)
		printf("\t                     %s\n", cert_types[i].name);

	printf("\t--output <file>  write signed data to <file>\n"
		"\t                  (default <sig-file>.siglist)\n");
}

static void version(void)
{
	char version[500];

	memset(version, 0, sizeof(version));
	lc_status(version, sizeof(version));

	fprintf(stderr, "Leancrypto %s\n", toolname);
	fprintf(stderr, "%s\n", version);
}

static int siglist_create(struct siglist_context *ctx)
{
	EFI_SIGNATURE_LIST *siglist;
	EFI_SIGNATURE_DATA *sigdata;
	uint32_t size;
	int ret = 0;

	if (ctx->type->sigsize && ctx->data_len != ctx->type->sigsize) {
		fprintf(stderr, "Error: signature lists of type '%s' expect "
					"%d bytes of data, "
					"%zd bytes provided.\n",
				ctx->type->name,
				ctx->type->sigsize,
				ctx->data_len);
		return -EINVAL;
	}

	size = (uint32_t)(sizeof(*siglist) + sizeof(*sigdata) + ctx->data_len);

	siglist = calloc(1, size);
	CKNULL(siglist, -ENOMEM);
	sigdata = (void *)(siglist + 1);

	siglist->SignatureType = ctx->type->guid;
	siglist->SignatureListSize = size;
	siglist->SignatureHeaderSize = 0;
	siglist->SignatureSize = (uint32_t)(ctx->data_len + sizeof(*sigdata));

	sigdata->SignatureOwner = ctx->owner;

	memcpy(sigdata->SignatureData, ctx->data, ctx->data_len);

	ctx->siglist = siglist;

out:
	return ret;
}

static int parse_guid(const char *str, EFI_GUID *guid)
{
	uint8_t uuid[16];
	int ret;

	CKINT(lc_uuid_hex2bin(str, strlen(str), uuid));

	/* convert to an EFI_GUID */
	guid->Data1 = (UINT32)(uuid[0] << 24 | uuid[1] << 16 | uuid[2] << 8 |
			       uuid[3]);
	guid->Data2 = (UINT16)(uuid[4] << 8 | uuid[5]);
	guid->Data3 = (UINT16)(uuid[6] << 8 | uuid[7]);
	memcpy(guid->Data4, &uuid[8], sizeof(guid->Data4));

out:
	return ret;
}

static struct cert_type *parse_type(const char *str)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cert_types); i++)
		if (!strcasecmp(cert_types[i].name, str))
			return &cert_types[i];

	return NULL;
}

static int set_default_outfilename(struct siglist_context *ctx)
{
	static const char *extension = "siglist";
	size_t len = strlen(ctx->infilename) + 1 + 7 + 1;
	int ret;

	CKINT(lc_alloc_aligned((void **)&ctx->outfilename, sizeof(uint64_t),
			       len));
	snprintf(ctx->outfilename, len, "%s.%s", ctx->infilename, extension);

out:
	return ret;
}

int main(int argc, char **argv)
{
	const char *type_str, *owner_guid_str;
	struct siglist_context ctx = { 0 };
	int c, ret;

	owner_guid_str = NULL;
	type_str = NULL;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "o:t:w:ivVh", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			ctx.outfilename = optarg;
			break;
		case 't':
			type_str = optarg;
			break;
		case 'w':
			owner_guid_str = optarg;
			break;
		case 'v':
			ctx.verbose = 1;
			break;
		case 'V':
			version();
			ret = 0;
			goto out;
		case 'h':
			usage();
			ret = 0;
			goto out;
		}
	}

	if (argc != optind + 1) {
		usage();
		ret = -EINVAL;
		goto out;
	}

	ctx.infilename = argv[optind];

	CKNULL_LOG(type_str, -EINVAL, "No type specified\n");
	CKNULL_LOG(owner_guid_str, -EINVAL, "No owner specified\n");

	ctx.type = parse_type(type_str);
	CKNULL_LOG(ctx.type, -EINVAL, "Invalid type '%s'\n", type_str);

	CKINT_LOG(parse_guid(owner_guid_str, &ctx.owner),
		  "Invalid owner GUID '%s'\n", owner_guid_str);

	if (!ctx.outfilename)
		CKINT(set_default_outfilename(&ctx));

	CKINT_LOG(get_data(ctx.infilename, &ctx.data, &ctx.data_len,
			   lc_pem_flag_nopem), "Can't read input file %s\n",
		  ctx.infilename);

	CKINT((siglist_create(&ctx)));

	CKINT_LOG(write_data(ctx.outfilename, (uint8_t *)ctx.siglist,
			     ctx.siglist->SignatureListSize, lc_pem_flag_nopem),
		  "Can't write output file %s\n", ctx.outfilename);

out:
	if (ctx.siglist)
		free(ctx.siglist);
	if (ctx.outfilename)
		lc_free(ctx.outfilename);
	release_data(ctx.data, ctx.data_len, lc_pem_flag_nopem);
	return -ret;
}
