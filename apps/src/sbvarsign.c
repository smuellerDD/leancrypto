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

#include <getopt.h>

#include "efivars.h"

#include "asn1.h"
#include "helper.h"
#include "lc_memory_support.h"
#include "lc_pkcs7_generator_helper.h"
#include "lc_status.h"
#include "x509_print.h"
#include "lc_x509_generator_file_helper.h"
#include "lc_uuid.h"
#include "ret_checkers.h"
#include "small_stack_support.h"

static const char *toolname = "sbvarsign";

struct varsign_context {
	const char *infilename;
	char *outfilename; // free

	uint8_t *data;
	size_t data_len;

	CHAR16 *var_name; //free
	size_t var_name_bytes; //int
	EFI_GUID var_guid;
	uint32_t var_attrs;

	int auth_descriptor_len;
	EFI_TIME timestamp;

	int verbose;
};

struct attr {
	const char *name;
	uint32_t value;
};

#define EFI_VAR_ATTR(n) { #n, EFI_VARIABLE_##n }
static struct attr attrs[] = {
	EFI_VAR_ATTR(NON_VOLATILE),
	EFI_VAR_ATTR(BOOTSERVICE_ACCESS),
	EFI_VAR_ATTR(RUNTIME_ACCESS),
	EFI_VAR_ATTR(TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
	EFI_VAR_ATTR(APPEND_WRITE),
};

static uint32_t default_attrs =
	EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
	EFI_VARIABLE_RUNTIME_ACCESS |
	EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS |
	EFI_VARIABLE_APPEND_WRITE;

static uint32_t attr_invalid = 0xffffffffu;
static const char *attr_prefix = "EFI_VARIABLE_";

static const EFI_GUID cert_pkcs7_guid = EFI_CERT_TYPE_PKCS7_GUID;

static int set_default_outfilename(struct varsign_context *ctx)
{
	static const char *extension = "signed";
	size_t len = strlen(ctx->infilename) + 1 + 6 + 1;
	int ret;

	CKINT(lc_alloc_aligned((void **)&ctx->outfilename, sizeof(uint64_t),
			       len));
	snprintf(ctx->outfilename, len, "%s.%s", ctx->infilename, extension);

out:
	return ret;
}

static uint32_t parse_single_attr(const char *attr_str)
{
	unsigned int i;

	/* skip standard prefix, if present */
	if (!strncmp(attr_str, attr_prefix, strlen(attr_prefix)))
		attr_str += strlen(attr_prefix);

	for (i = 0; i < ARRAY_SIZE(attrs); i++) {
		if (!strcmp(attr_str, attrs[i].name))
			return attrs[i].value;
	}

	return attr_invalid;
}

static uint32_t parse_attrs(const char *attrs_str)
{
	uint32_t attr, attrs_val;
	const char *attr_str;
	char *str;

	/* we always need E_V_T_B_A_W_A */
	attrs_val = EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

	if (!attrs_str[0])
		return attrs_val;

	str = strdup(attrs_str);

	for (attr_str = strtok(str, ","); attr_str;
	     attr_str = strtok(NULL, ",")) {
		attr = parse_single_attr(attr_str);
		if (attr == attr_invalid) {
			fprintf(stderr, "Invalid attribute string %s\n",
				attr_str);
			return attr_invalid;
		}

		attrs_val |= attr;
	}

	return attrs_val;
}

static int set_varname(struct varsign_context *ctx, const char *str)
{
	CHAR16 *wstr;
	size_t i, len;
	int ret = 0;

	len = strlen(str);

	wstr = calloc(len, sizeof(CHAR16));
	CKNULL(wstr, -ENOMEM);

	for (i = 0; i < len; i++)
		wstr[i] = (CHAR16)str[i];

	ctx->var_name = wstr;
	ctx->var_name_bytes = len * sizeof(CHAR16);

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

static int set_timestamp(EFI_TIME *timestamp)
{
	struct tm *tm;
	time_t t;

	time(&t);

	tm = gmtime(&t);
	if (!tm) {
		perror("gmtime");
		return -EFAULT;
	}

	/* copy to our EFI-specific time structure. Other fields (Nanosecond,
	 * TimeZone, Daylight and Pad) are defined to be zero */
	memset(timestamp, 0, sizeof(*timestamp));
	timestamp->Year = (UINT16)(1900 + tm->tm_year);
	timestamp->Month = (UINT8)tm->tm_mon;
	timestamp->Day = (UINT8)tm->tm_mday;
	timestamp->Hour = (UINT8)tm->tm_hour;
	timestamp->Minute = (UINT8)tm->tm_min;
	timestamp->Second = (UINT8)tm->tm_sec;

	return 0;
}

static int write_signed(struct varsign_context *ctx, int include_attrs,
			EFI_VARIABLE_AUTHENTICATION_2 *auth_descriptor,
			size_t auth_descriptor_len)
{
	int fd, ret;

	fd = open(ctx->outfilename, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}

	/*
	 * For some uses (eg, writing to the efivars filesystem), we may
	 * want to prefix the signed variable with four bytes of attribute
	 * data
	 */
	if (include_attrs) {
		CKINT(x509_write_data(fd, (uint8_t *)&ctx->var_attrs,
				      sizeof(ctx->var_attrs)));
	}

	/* Write the authentication descriptor */
	CKINT(x509_write_data(fd, (uint8_t *)auth_descriptor,
			      auth_descriptor_len));

	/* ... and the variable data itself */
	CKINT(x509_write_data(fd, ctx->data, ctx->data_len));

	if (ctx->verbose) {
		size_t i = 0;

		printf("Wrote signed data:\n");
		if (include_attrs) {
			i = sizeof(ctx->var_attrs);
			printf("  [%04lx:%04zx] attrs\n", 0l, i);
		}

		printf("  [%04zx:%04x] authentication descriptor\n", i,
		       ctx->auth_descriptor_len);

		printf("    [%04zx:%04zx] EFI_VAR_AUTH_2 header\n", i,
		       sizeof(EFI_VARIABLE_AUTHENTICATION_2));

		printf("    [%04zx:%04zx] WIN_CERT_UEFI_GUID header\n",
		       i + offsetof(EFI_VARIABLE_AUTHENTICATION_2, AuthInfo),
		       sizeof(WIN_CERTIFICATE_UEFI_GUID));

		printf("    [%04zx:%04zx] WIN_CERT header\n",
		       i + offsetof(EFI_VARIABLE_AUTHENTICATION_2,
				    AuthInfo.Hdr),
		       sizeof(WIN_CERTIFICATE));

		printf("    [%04zx:%04zx] pkcs7 data\n",
		       i + offsetof(EFI_VARIABLE_AUTHENTICATION_2,
				    AuthInfo.CertData),
		       auth_descriptor_len -
			       sizeof(EFI_VARIABLE_AUTHENTICATION_2));

		i += auth_descriptor_len;

		printf("  [%04zx:%04zx] variable data\n", i, i + ctx->data_len);
	}

out:
	if (fd >= 0)
		close(fd);
	return ret;
}

static int hash_data(const struct varsign_context *ctx, EFI_TIME *timestamp,
		     uint8_t **buf, size_t *buflen)
{
	uint8_t *buf_p;
	int ret;

	/*
	 * create a BIO for our variable data, containing:
	 *  * Variablename (not including trailing nul)
	 *  * VendorGUID
	 *  * Attributes
	 *  * TimeStamp
	 *  * Data
	 */
	*buflen = ctx->var_name_bytes + sizeof(ctx->var_guid) +
		  sizeof(ctx->var_attrs) + sizeof(EFI_TIME) + ctx->data_len;
	CKINT(lc_alloc_aligned((void **)buf, sizeof(uint64_t), *buflen));
	buf_p = *buf;
	memcpy(buf_p, ctx->var_name, ctx->var_name_bytes);
	buf_p += ctx->var_name_bytes;
	memcpy(buf_p, &ctx->var_guid, sizeof(ctx->var_guid));
	buf_p += sizeof(ctx->var_guid);
	memcpy(buf_p, &ctx->var_attrs, sizeof(ctx->var_attrs));
	buf_p += sizeof(ctx->var_attrs);
	memcpy(buf_p, timestamp, sizeof(EFI_TIME));
	buf_p += sizeof(EFI_TIME);
	memcpy(buf_p, ctx->data, ctx->data_len);

out:
	return ret;
}

static int verify_auth_descriptor(struct pkcs7_generator_opts *opts,
				  struct varsign_context *ctx,
				  EFI_VARIABLE_AUTHENTICATION_2 *auth_descriptor,
				  size_t auth_descriptor_len)
{
	const uint8_t *avail_data,
	      *pkcs7_data = (uint8_t *)auth_descriptor +
			     sizeof(EFI_VARIABLE_AUTHENTICATION_2);
	uint8_t *buf = NULL;
	size_t avail_datalen, buflen,
	       pkcs7_datalen = auth_descriptor_len -
			       sizeof(EFI_VARIABLE_AUTHENTICATION_2);
	PKCS7_ALLOC
	int ret;

	CKINT_LOG(lc_pkcs7_decode(pkcs7_msg, pkcs7_data, pkcs7_datalen),
		  "Parsing of input file %s failed\n", opts->pkcs7_msg);

	CKINT(hash_data(ctx, &auth_descriptor->TimeStamp, &buf, &buflen));

	CKINT(lc_pkcs7_set_data(pkcs7_msg, buf, buflen, 0))

	/*
	 * Now, if we have data with the PKCS7 message, attempt to verify it
	 * (i.e. perform a signature verification).
	 */
	CKINT(lc_pkcs7_get_content_data(pkcs7_msg, &avail_data, &avail_datalen));

	ret = lc_pkcs7_verify(
		pkcs7_msg,
		opts->use_trust_store ? &opts->trust_store : NULL,
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
			ret = 0;
		}
	}

	CKINT(print_pkcs7_data(pkcs7_msg));

out:
	lc_free(buf);
	lc_pkcs7_message_clear(pkcs7_msg);
	PKCS7_FREE
	return ret;
}

static int add_auth_descriptor(struct pkcs7_generator_opts *opts,
			       struct varsign_context *ctx, int include_attrs)
{
#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma GCC diagnostic ignored "-Wpedantic"
	struct workspace {
		/*
		 * Auth and data must be aligned as both act as one linear
		 * buffer.
		 */
		EFI_VARIABLE_AUTHENTICATION_2 auth;
		uint8_t data[ASN1_MAX_DATASIZE];
		EFI_TIME timestamp;
	};
#pragma GCC diagnostic pop
	EFI_VARIABLE_AUTHENTICATION_2 *auth;
	size_t buflen, avail_datalen, datalen;
	uint8_t *buf = NULL;
	struct lc_pkcs7_message *pkcs7 = opts->pkcs7;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(get_data(ctx->infilename, &ctx->data, &ctx->data_len,
		       lc_pem_flag_nopem));

	CKINT(set_timestamp(&ws->timestamp));

	CKINT(hash_data(ctx, &ws->timestamp, &buf, &buflen));

	CKINT(lc_pkcs7_set_data(pkcs7, buf, buflen, 0));

	avail_datalen = ASN1_MAX_DATASIZE;
	CKINT_LOG(lc_pkcs7_encode(pkcs7, ws->data, &avail_datalen),
		  "Error signing variable data\n");
	datalen = ASN1_MAX_DATASIZE - avail_datalen;

	auth = &ws->auth;
	auth->TimeStamp = ws->timestamp;
	auth->AuthInfo.Hdr.dwLength =
		(UINT32)(datalen + sizeof(auth->AuthInfo));
	auth->AuthInfo.Hdr.wRevision = 0x0200;
	auth->AuthInfo.Hdr.wCertificateType = 0x0EF1;
	auth->AuthInfo.CertType = cert_pkcs7_guid;

	/*
	 * write the resulting image
	 *
	 * This invocation writes the linear buffer of ws->auth || ws->data.
	 */
	CKINT(write_signed(ctx, include_attrs, auth, sizeof(*auth) + datalen));

	if (opts->print_pkcs7)
		CKINT(verify_auth_descriptor(opts, ctx, auth,
					     sizeof(*auth) + datalen));

out:
	lc_free(buf);
	release_data(ctx->data, ctx->data_len, lc_pem_flag_nopem);
	LC_RELEASE_MEM(ws);
	return ret;
}

static void set_default_guid(struct varsign_context *ctx, const char *varname)
{
	EFI_GUID secdb_guid = EFI_IMAGE_SECURITY_DATABASE_GUID;
	EFI_GUID global_guid = EFI_GLOBAL_VARIABLE;

	if (!strcmp(varname, "db") || !strcmp(varname, "dbx"))
		ctx->var_guid = secdb_guid;
	else
		ctx->var_guid = global_guid;
}

static struct option options[] = {
	{ "output", required_argument, NULL, 'o' },
	{ "guid", required_argument, NULL, 'g' },
	{ "attrs", required_argument, NULL, 'a' },
	{ "key", required_argument, NULL, 'k' },
	{ "cert", required_argument, NULL, 'c' },
	{ "include-attrs", no_argument, NULL, 'i' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ "engine", required_argument, NULL, 'e' },
	{ "print", no_argument, NULL, 'p' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	unsigned int i;

	printf("Usage: %s [options] --key <keyfile> --cert <certfile> "
	       "<var-name> <var-data-file>\n"
	       "Sign a blob of data for use in SetVariable().\n\n"
	       "Options:\n"
	       "\t--engine <eng>     use the specified engine to load the key\n"
	       "\t--key <keyfile>    signing key (PEM or DER)\n"
	       "\t--cert <certfile>  certificate (x509 certificate)\n"
	       "\t--include-attrs    include attrs at beginning of output file\n"
	       "\t--guid <GUID>      EFI GUID for the variable. If omitted,\n"
	       "\t                    EFI_IMAGE_SECURITY_DATABASE or\n"
	       "\t                    EFI_GLOBAL_VARIABLE (depending on\n"
	       "\t                    <var-name>) will be used.\n"
	       "\t--attr <attrs>     variable attributes. One or more of:\n",
	       toolname);

	for (i = 0; i < ARRAY_SIZE(attrs); i++)
		printf("\t                     %s\n", attrs[i].name);

	printf("\t                    Separate multiple attrs with a comma,\n"
	       "\t                    default is all attributes,\n"
	       "\t                    TIME_BASED_AUTH... is always included.\n"
	       "\t--output <file>    write signed data to <file>\n"
	       "\t                    (default <var-data-file>.signed)\n"
	       "\t--print            Verify OPKCS#7 message and print content\n"
	);
}

static void version(void)
{
	char version[500];

	memset(version, 0, sizeof(version));
	lc_status(version, sizeof(version));

	fprintf(stderr, "Leancrypto %s\n", toolname);
	fprintf(stderr, "%s\n", version);
}

int main(int argc, char **argv)
{
	PKCS7_ALLOC
	struct workspace {
		struct pkcs7_generator_opts parsed_opts;
		struct varsign_context ctx;
	};
	struct varsign_context *ctx;
	int ret, c, include_attrs = 0;
	const char *guid_str = NULL, *attr_str = NULL, *varname;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	ctx = &ws->ctx;
	/*
	 * This tool defaults to SHA2-512. The original sbsign tool uses
	 * SHA2-256. However, The security strength of SHA2-256 is 128 bits and
	 * thus too low for ML-DSA65 or 87. Considering that all PQC algos
	 * require the presence of Keccak, using SHA3 makes more sense - it
	 * would not artifically require to add the presence of SHA2-512 support
	 * to the library. But then, NIAP with their, well, statement in CNSA
	 * 2.0 to not allow SHA3 would be violated. Thus, we leave SHA2-512 here
	 * for now.
	 *
	 * Furthermore, RFC9882 section 3.3 suggests the use of SHA2-512 as a
	 * default.
	 */
	ws->parsed_opts.hash = lc_sha512;
	ws->parsed_opts.pkcs7 = pkcs7_msg;

	/* To comply with RFC9882, we use authenticated attributes. */
	ws->parsed_opts.aa_set = sinfo_has_content_type |
				 sinfo_has_signing_time |
				 sinfo_has_message_digest;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "o:g:a:k:c:ivVhe:", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			ctx->outfilename = optarg;
			break;
		case 'g':
			guid_str = optarg;
			break;
		case 'a':
			attr_str = optarg;
			break;
		case 'c':
			ws->parsed_opts.x509_signer_file = optarg;
			CKINT(pkcs7_collect_signer(&ws->parsed_opts));
			break;
		case 'k':
			ws->parsed_opts.signer_sk_file = optarg;
			CKINT(pkcs7_collect_signer(&ws->parsed_opts));
			break;
		case 'i':
			include_attrs = true;
			break;
		case 'v':
			ctx->verbose = 1;
			break;
		case 'V':
			version();
			ret = 0;
			goto out;
		case 'h':
			usage();
			ret = 0;
			goto out;
		case 'e':
			printf("Engine option ignored\n");
			break;
		case 'p':
			ws->parsed_opts.print_pkcs7 = true;
			break;
		}
	}

	if (argc != optind + 2) {
		usage();
		ret = -EINVAL;
		goto out;
	}

	/* set up the variable signing context */
	varname = argv[optind];
	set_varname(ctx, varname);
	ctx->infilename = argv[optind + 1];

	if (!ctx->outfilename)
		set_default_outfilename(ctx);

	if (attr_str) {
		ctx->var_attrs = parse_attrs(attr_str);
		if (ctx->var_attrs == attr_invalid)
			return EXIT_FAILURE;
	} else {
		ctx->var_attrs = default_attrs;
	}

	if (guid_str) {
		if (parse_guid(guid_str, &ctx->var_guid)) {
			fprintf(stderr, "Invalid GUID '%s'\n", guid_str);
			return EXIT_FAILURE;
		}
	} else {
		set_default_guid(ctx, varname);
	}

	/* do the signing */
	CKINT((add_auth_descriptor(&ws->parsed_opts, ctx, include_attrs)));

out:
	LC_RELEASE_MEM(ws);
	PKCS7_FREE
	return -ret;
}
