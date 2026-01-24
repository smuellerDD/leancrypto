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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#include <getopt.h>

#include "image.h"

#include "asn1.h"
#include "lc_pkcs7_generator_helper.h"
#include "lc_x509_generator_file_helper.h"
#include "ret_checkers.h"
#include "lc_status.h"
#include "small_stack_support.h"
#include "x509_print.h"

static const char *toolname = "sbattach";

static struct option options[] = {
	{ "attach", required_argument, NULL, 'a' },
	{ "detach", required_argument, NULL, 'd' },
	{ "remove", no_argument, NULL, 'r' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ "signum", required_argument, NULL, 's' },
	{ "print", no_argument, NULL, 'p' },
	{ "cert", required_argument, NULL, 'c' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s --attach <sigfile> <efi-boot-image>\n"
	       "   or: %s --detach <sigfile> [--remove] <efi-boot-image>\n"
	       "   or: %s --remove <efi-boot-image>\n"
	       "Attach or detach a signature file to/from a boot image\n"
	       "\n"
	       "Options:\n"
	       "\t--attach <sigfile>  set <sigfile> as the boot image's\n"
	       "\t                     signature table\n"
	       "\t--detach <sigfile>  copy the boot image's signature table\n"
	       "\t                     to <sigfile>\n"
	       "\t--remove            remove the boot image's signature\n"
	       "\t                     table from the original file\n"
	       "\t--signum            signature to operate on (defaults to\n"
	       "\t                     first)\n"
	       "\t--print             Verify PKCS#7 message and print content\n"
	       "\t--cert <certfile>   certificate (x509 certificate) used for\n"
	       "                       PKCS#7 verification with --print",
	       toolname, toolname, toolname);
}

static void version(void)
{
	char version[500];

	memset(version, 0, sizeof(version));
	lc_status(version, sizeof(version));

	fprintf(stderr, "Leancrypto %s\n", toolname);
	fprintf(stderr, "%s\n", version);
}

static int detach_sig(struct image *image, unsigned int signum,
		      const char *sig_filename)
{
	/*
	 * Write a duplicate of the signature in the PE/COFF file to a
	 * separate file.
	 */
	return image_write_detached(image, signum, sig_filename);
}

static int pkcs7_ver_message_sbattach(struct pkcs7_generator_opts *opts,
				      const uint8_t *pkcs7_data,
				      size_t pkcs7_datalen)
{
	struct lc_pkcs7_parse_context ctx;
	uint8_t *buf = NULL;
	PKCS7_ALLOC
	int ret;

	/* Initialize the encoding context */
	CKINT(lc_pkcs7_decode_ctx_init(&ctx));

	/*
	 * Expect the data content to be SpcIndirectDataContent
	 * using SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4).
	 */
	CKINT(lc_pkcs7_decode_ctx_set_aa_content_type(&ctx,
						      OID_msIndirectData));

	/* Set the PKCS#7 message structure to be decoded into. */
	CKINT(lc_pkcs7_decode_ctx_set_pkcs7(&ctx, pkcs7_msg));

	/* Perform the actual message decoding. */
	CKINT_LOG(lc_pkcs7_decode_ctx(&ctx, pkcs7_data, pkcs7_datalen),
		  "Parsing of input data failed\n");

	/*
	 * Verify the PKCS#7 message data.
	 * No data needs to be set as all data is embedded into the PKCS#7
	 * message as documented in sbsign.c:pkcs7_gen_message_sbsign.
	 */
	ret = lc_pkcs7_verify(
		pkcs7_msg, opts->use_trust_store ? &opts->trust_store : NULL,
		opts->verify_rules_set ? &opts->verify_rules : NULL);
	if (!opts->skip_signature_verification) {
		if (ret) {
			printf("Verification of PKCS#7 message failed\n");
			goto out;
		}
	} else {
		if (ret == -EBADMSG) {
			printf("AA: Message digest size mismatch\n");
			goto out;
		} else if (ret == -EKEYREJECTED) {
			printf("AA: No message digest or digest mismatch\n");
			goto out;
		} else if (ret == -ENOKEY) {
			printf("No signer found - skipping signature verification as requested\n");
		}
	}

	if (opts->print_pkcs7)
		CKINT(print_pkcs7_data(pkcs7_msg));

out:
	lc_free(buf);
	lc_pkcs7_message_clear(pkcs7_msg);
	lc_pkcs7_decode_ctx_clear(&ctx);
	PKCS7_FREE
	return ret;
}

static int attach_sig(struct pkcs7_generator_opts *opts, struct image *image,
		      const char *image_filename, const char *sig_filename)
{
	struct workspace {
		struct image image;
		uint8_t data[ASN1_MAX_DATASIZE];
	};
	uint8_t *sigbuf;
	size_t size;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* Read the file with the signature to be added */
	CKINT(get_data(sig_filename, &sigbuf, &size, lc_pem_flag_nopem));

	/* Verify the signature as a safety precaution */
	CKINT(pkcs7_ver_message_sbattach(opts, sigbuf, size));

	/* Add the signature to the PE/COFF file */
	CKINT(image_add_signature(image, sigbuf, size));

	/* Write the PE/COFF structure out to file */
	CKINT_LOG(image_write(image, image_filename), "Error writing %s: %s\n",
		  image_filename, strerror(errno));

out:
	release_data(sigbuf, size, lc_pem_flag_nopem);
	image_release(&ws->image);
	LC_RELEASE_MEM(ws);
	return ret;
}

static int remove_sig(struct image *image, unsigned int signum,
		      const char *image_filename)
{
	int ret;

	/* Remove the signature from the PE/COFF file referenced by signum */
	CKINT_LOG(image_remove_signature(image, signum),
		  "Error, image has no signature at %u\n", signum + 1);

	/* Write the PE/COFF structure out to file */
	CKINT_LOG(image_write(image, image_filename), "Error writing %s: %s\n",
		  image_filename, strerror(errno));

out:
	return ret;
}

enum action {
	ACTION_NONE,
	ACTION_ATTACH,
	ACTION_DETACH,
};

int main(int argc, char **argv)
{
	struct workspace {
		struct image image;
		struct pkcs7_generator_opts parsed_opts;
	};
	uint8_t *image_buf = NULL;
	size_t image_size = 0;
	unsigned long val;
	enum action action;
	int c, ret = 0;
	unsigned int signum = 0;
	bool remove;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	action = ACTION_NONE;
	remove = false;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "a:d:s:rhVp", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'a':
		case 'd':
			if (action != ACTION_NONE) {
				fprintf(stderr, "Multiple actions specified\n");
				usage();
				ret = -EINVAL;
				goto out;
			}
			action = (c == 'a') ? ACTION_ATTACH : ACTION_DETACH;
			ws->parsed_opts.outfile = optarg;
			break;
		case 's':
			val = strtoul(optarg, NULL, 10);
			if (val >= UINT_MAX)
				return -EINVAL;

			/* humans count from 1 not zero */
			signum = (unsigned int)val - 1;
			break;
		case 'r':
			remove = true;
			break;
		case 'V':
			version();
			goto out;
		case 'h':
			usage();
			goto out;
		case 'p':
			ws->parsed_opts.print_pkcs7 = true;
			break;
		case 'c':
			ws->parsed_opts.trust_anchor = optarg;
			CKINT(pkcs7_collect_trust(&ws->parsed_opts));
			break;
			/*
		 * NOTE: we also could check for EKU/key usage during PKCS#7
		 * verify:
		 */
#if 0
		/* expected-keyusage */
		case 13:
			CKINT(lc_x509_name_to_keyusage(
				optarg,
				&verify_rules->required_keyusage));
			parsed_opts.verify_rules_set = 1;
			break;
		/* expected-eku */
		case 14:
			CKINT(lc_x509_name_to_eku(
				optarg, &verify_rules->required_eku));
			parsed_opts.verify_rules_set = 1;
			break;
#endif
		}
	}

	if (argc != optind + 1) {
		usage();
		ret = -EINVAL;
		goto out;
	}
	ws->parsed_opts.infile = argv[optind];

	/* sanity check action combinations */
	if (action == ACTION_ATTACH && remove) {
		fprintf(stderr, "Can't use --remove with --attach\n");
		ret = -EINVAL;
		goto out;
	}

	if (action == ACTION_NONE && !remove) {
		fprintf(stderr, "No action (attach/detach/remove) specified\n");
		usage();
		ret = -EINVAL;
		goto out;
	}

	/* Read the PE/COFF file into memory to allow it to be modified */
	CKINT(get_data_memory(ws->parsed_opts.infile, &image_buf, &image_size,
			      lc_pem_flag_nopem));

	/* Parse the image */
	CKINT_LOG(image_load(image_buf, image_size, &ws->image),
		  "Can't load image file %s\n", ws->parsed_opts.infile);

	if (action == ACTION_ATTACH) {
		CKINT(attach_sig(&ws->parsed_opts, &ws->image,
				 ws->parsed_opts.infile,
				 ws->parsed_opts.outfile));
	} else if (action == ACTION_DETACH) {
		CKINT(detach_sig(&ws->image, signum, ws->parsed_opts.outfile));
	}

	if (remove) {
		CKINT(remove_sig(&ws->image, signum, ws->parsed_opts.infile));
	}

out:
	release_data_memory(image_buf, image_size, lc_pem_flag_nopem);
	pkcs7_clean_opts(&ws->parsed_opts);
	image_release(&ws->image);
	LC_RELEASE_MEM(ws);
	return -ret;
}
