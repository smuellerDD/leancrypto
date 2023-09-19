/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <ctype.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "ext_headers.h"

#include "binhexbin.h"
#include "hasher_app.h"
#include "lc_status.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "ret_checkers.h"

struct hasher_options {
	unsigned int quiet : 1;
	unsigned int status : 1;
	unsigned int tag : 1;
	unsigned int null : 1;
	const char *checkfile;
	const char *bsdname;
};

static int hasher_get_trailing(const char *string, const char **found)
{
	size_t len;
	unsigned int numsep = 0;
	const char *string_p = string;
	const char *saveptr = NULL;

	if (!string)
		return 0;

	len = strlen(string);

	/* Finding the pointer of the last slash */
	while (len) {
		/* search for slash */
		if (*string_p == 47) {
			saveptr = string_p;
			numsep++;

			if (numsep >= 256)
				return -EINVAL;
		}

		string_p++;
		len--;
	}

	/* tailing character is a slash */
	if (saveptr == string_p) {
		fprintf(stderr, "Trailing character of string %s is a slash\n",
			string);
		return -EINVAL;
	}

	*found = saveptr + 1;
	return 0;
}

static void hasher_version(const char *name)
{
	const char *base;
	char version[100];

	memset(version, 0, sizeof(version));
	lc_status(version, sizeof(version));

	if (hasher_get_trailing(name, &base))
		fprintf(stderr, "%s", version);
	else
		fprintf(stderr, "%s: %s", (name), version);
}

static void hasher_usage(const char *name)
{
	const char *base_file = "";

	if (hasher_get_trailing(name, &base_file))
		base_file = "";

	fprintf(stderr, "\n%s - calculation of hash sum (Using leancrypto)\n",
		base_file);

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t%s [OPTION]... FILE...\n", base_file);

	fprintf(stderr, "\nOptions:\n");

	fprintf(stderr, "\t-c --check FILE\t\tVerify hash sums from file\n");
	fprintf(stderr, "\t-q --status\t\tSuppress verification output\n");
	fprintf(stderr, "\t   --quiet\t\tSuppress only success messages\n");
	fprintf(stderr, "\t   --tag\t\tCreate a BSD-style checksum\n");
	fprintf(stderr,
		"\t-b, -P\t\t\tCompatibility hmaccalc options; ignored\n");
	fprintf(stderr, "\t-z\t\t\tNUL line termination\n");
	fprintf(stderr, "\t   --help\t\tPrint this help text\n");
	fprintf(stderr, "\t-v --version\t\tShow version\n");
}

static void hasher_free_options(struct hasher_options *parsed_opts)
{
	if (!parsed_opts)
		return;

	memset(parsed_opts, 0, sizeof(struct hasher_options));
}

static int check_filetype(int fd, struct stat *sb)
{
	int ret = fstat(fd, sb);

	if (ret)
		return -errno;

	/* Do not return an error in case we cannot validate the data. */
	if ((sb->st_mode & S_IFMT) != S_IFREG &&
	    (sb->st_mode & S_IFMT) != S_IFLNK)
		return -EINVAL;

	return 0;
}

static void hasher_bin2print(const uint8_t *bin, size_t binlen,
			     const char *filename, FILE *outfile, uint32_t lfcr)
{
	char *hex;
	size_t hexlen = binlen * 2 + 1;

	hex = calloc(1, hexlen);
	if (!hex)
		return;
	bin2hex(bin, binlen, hex, hexlen - 1, 0);
	/* fipshmac does not want the file name :-( */
	if (outfile != stdout)
		fprintf(outfile, "%s", hex);
	else if (filename)
		fprintf(outfile, "%s  %s", hex, filename);
	else
		fprintf(outfile, "%s", hex);

	if (lfcr)
		fputc(0x0a, outfile);
	else
		fputc(0x00, outfile);

	free(hex);
}

static int mmap_file(const char *filename, uint8_t **memory, off_t *size,
		     size_t *mapped, off_t offset)
{
	int fd = -1;
	int ret = 0;
	struct stat sb;

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open file %s: %s\n", filename,
			strerror(errno));
		return -EIO;
	}

	if (*size) {
		if ((*size - offset) < (off_t)*mapped)
			*mapped = (size_t)(*size - offset);
	} else {
		CKINT(check_filetype(fd, &sb));
		*size = sb.st_size;
		if (*size <= (off_t)*mapped) {
			*mapped = (size_t)*size;
			if (*size == 0)
				goto out;
		}
	}

	*memory = mmap(NULL, *mapped, PROT_READ,
		       MAP_PRIVATE
#ifdef __linux__
			       | MAP_POPULATE
#endif
		       ,
		       fd, offset);
	if (*memory == MAP_FAILED) {
		*memory = NULL;
		ret = -errno;
		goto out;
	}
	madvise(*memory, *mapped, MADV_SEQUENTIAL | MADV_WILLNEED);

out:
	close(fd);
	return ret;
}

static int hasher(struct lc_hash_ctx *hash_ctx,
		  const struct hasher_options *parsed_opts,
		  const char *filename, const char *comphash,
		  uint32_t comphashlen, FILE *outfile)
{
	/* Mapping file in 16M segments */
	size_t mapped = 16 << 20, hashlen = lc_hash_digestsize(hash_ctx);
	off_t offset = 0, size = 0;
	uint8_t *memblock = NULL;
	uint8_t md[64];
	int ret = 0;

	if (filename) {
		do {
			CKINT(mmap_file(filename, &memblock, &size, &mapped,
					offset));

			/* Compute hash */
			lc_hash_update(hash_ctx, memblock, mapped);

			munmap(memblock, mapped);
			offset = offset + (off_t)mapped;

		} while (offset ^ size);
	} else {
		uint8_t tmpbuf[4096];
		uint32_t bufsize;

		while ((bufsize = (uint32_t)fread(tmpbuf, sizeof(uint8_t),
						  sizeof(tmpbuf), stdin))) {
			lc_hash_update(hash_ctx, tmpbuf, bufsize);
		}
		lc_memset_secure(tmpbuf, 0, sizeof(tmpbuf));
	}

	lc_hash_final(hash_ctx, md);

	if (comphash && comphashlen) {
		uint8_t compmd[64];

		memset(compmd, 0, sizeof(compmd));
		hex2bin(comphash, comphashlen, compmd, sizeof(compmd));
		if ((comphashlen != hashlen * 2) ||
		    memcmp(compmd, md, hashlen)) {
			ret = -EBADMSG;
			goto out;
		}
	} else {
		if (outfile == NULL) {
			hasher_bin2print(md, hashlen, NULL, stdout,
					 !parsed_opts->null);
		} else if (parsed_opts->tag) {
			fprintf(outfile, "%s (%s) = ", parsed_opts->bsdname,
				filename ? filename : "-");
			hasher_bin2print(md, hashlen, NULL, outfile,
					 !parsed_opts->null);
		} else {
			hasher_bin2print(md, hashlen, filename ? filename : "-",
					 outfile, !parsed_opts->null);
		}
	}

out:
	return ret;
}

static int hasher_files(const struct hasher_options *parsed_opts,
			char *filenames[], uint32_t files,
			struct lc_hash_ctx *hash_ctx)
{
	uint32_t i = 0;
	int ret = 0;

	if (!files)
		return -EINVAL;

	lc_hash_init(hash_ctx);

	for (i = 0; i < files; i++) {
		FILE *out = stdout;
		const char *filename = filenames[i];

		if (strcmp(filename, "-") == 0)
			filename = NULL;

		CKINT(hasher(hash_ctx, parsed_opts, filename, NULL, 0, out));
	}

out:
	return ret;
}

static int hasher_checkfile(const struct hasher_options *parsed_opts,
			    struct lc_hash_ctx *hash_ctx)
{
	FILE *file = NULL;
	int ret = 0;
	int checked_any = 0;

	/*
	 * A file can have up to 4096 characters, so a complete line has at most
	 * 4096 bytes (file name) + 128 bytes (SHA512 hex value) + 2 spaces +
	 * one byte for the CR.
	 */
	char buf[(4096 + 128 + 2 + 1)];

	lc_hash_init(hash_ctx);

	file = strcmp(parsed_opts->checkfile, "-") ?
		       fopen(parsed_opts->checkfile, "r") :
		       stdin;
	if (!file) {
		fprintf(stderr, "Cannot open file %s\n",
			parsed_opts->checkfile);
		ret = -EIO;
		goto out;
	}

	while (fgets(buf, sizeof(buf), file)) {
		char *filename = NULL; // parsed file name
		char *hexhash = NULL; // parsed hex value of hash
		uint32_t hexhashlen = 0; // length of hash hex value
		uint32_t linelen = (uint32_t)strlen(buf);
		uint32_t i;
		uint32_t bsd_style = 0; // >0 if --tag formatted style

		if (linelen == 0)
			break;

		/* remove trailing CR and reduce buffer length */
		for (i = linelen - 1; i > 0; i--) {
			if (!isprint(buf[i])) {
				buf[i] = '\0';
				linelen--;
			} else
				break;
		}

		for (i = 1; i < linelen; i++) {
			/*
			 * Check for BSD-style separator between file name and
			 * hash value.
			 */
			if (((linelen - i) >= 3) && isblank(buf[i]) &&
			    buf[i + 1] == '=' && isblank(buf[i + 2])) {
				/* Start of hash value */
				bsd_style = i + 3;
				hexhash = buf + bsd_style;
				break;
			}
		}

		for (i = 0; i < linelen; i++) {
			/* file name / hash separator for regular case */
			if (!bsd_style && isblank(buf[i])) {
				filename = buf + i;
				break;
			}

			/* Count hash bytes */
			if (!bsd_style && !filename)
				hexhashlen++;

			/* Find file name start value of BSD-style. */
			if (bsd_style && (linelen - i) >= 2 &&
			    isblank(buf[i]) && buf[i + 1] == '(') {
				filename = buf + i + 2;
				break;
			}
		}

		/* In regular case, hash starts at the beginning of buffer. */
		if (!bsd_style)
			hexhash = buf;

		if (bsd_style) {
			/* Hash starts after separator */
			hexhashlen = linelen - bsd_style + 1;

			/* remove closing parenthesis behind filename */
			if (buf[(bsd_style - 4)] == ')')
				buf[(bsd_style - 4)] = '\0';
		}

		if (!hexhash || !hexhashlen) {
			fprintf(stderr, "Invalid checkfile format\n");
			ret = 1;
			goto out;
		}

		if (filename) {
			int r;

			if (!bsd_style) {
				if (!isblank(filename[0]) ||
				    (!isblank(filename[1]) &&
				     filename[1] != '*')) {
					fprintf(stderr,
						"Invalid checkfile format\n");
					ret = 1;
					goto out;
				}
				filename += 2;
			}

			r = hasher(hash_ctx, parsed_opts, filename, hexhash,
				   hexhashlen, stdout);

			if (r == 0) {
				if (!parsed_opts->quiet && !parsed_opts->status)
					printf("%s: OK\n", filename);
			} else {
				printf("%s: Not OK\n", filename);
				if (ret >= 0)
					ret++;
			}
			checked_any = 1;
		}
	}

out:
	if (file)
		fclose(file);

	/*
	 * If we found no lines to check, return an error.
	 * (See https://pagure.io/hmaccalc/c/1afb99549816192eb8e6bc8101bc417c2ffa764c)
	 */
	return ret ? ret : (checked_any ? 0 : -EINVAL);
}

int hasher_main(int argc, char *argv[], const struct lc_hash *hash)
{
	struct hasher_options parsed_opts = { 0 };
	int ret = 0, opt_index = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, hash);

	static const char *opts_short = "c:qbPzv";
	static const struct option opts[] = {
		{ "help", 0, 0, 0 },	 { "version", 0, 0, 'v' },
		{ "tag", 0, 0, 0 },	 { "quiet", 0, 0, 0 },
		{ "status", 0, 0, 'q' }, { "check", 1, 0, 'c' },
		{ 0, 0, 0, 0 }
	};

	opterr = 0;
	while (1) {
		int c = getopt_long(argc, argv, opts_short, opts, &opt_index);

		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			/* help */
			case 0:
				hasher_usage(argv[0]);
				goto out;

			/* version */
			case 1:
				hasher_version(argv[0]);
				goto out;

			/* tag */
			case 2:
				parsed_opts.tag = 1;
				break;

			/* quiet */
			case 3:
				parsed_opts.quiet = 1;
				break;
			}
			break;

		case 'v':
			hasher_version(argv[0]);
			goto out;

		case 'b':
		case 'P':
			/* Compatibility options, just ignore */
			break;
		case 'z':
			parsed_opts.null = 1;
			break;

		case 'q':
			parsed_opts.status = 1;
			break;

		case 'c':
			parsed_opts.checkfile = optarg;
			break;

		default:
			hasher_usage(argv[0]);
			ret = 1;
			goto out;
		}
	}

	if (hash == lc_sha256)
		parsed_opts.bsdname = "SHA256";
	else if (hash == lc_sha512)
		parsed_opts.bsdname = "SHA512";
	else if (hash == lc_sha3_256)
		parsed_opts.bsdname = "SHA3-256";
	else if (hash == lc_sha3_384)
		parsed_opts.bsdname = "SHA3-384";
	else if (hash == lc_sha3_256)
		parsed_opts.bsdname = "SHA3-512";

	if (!parsed_opts.checkfile)
		ret = hasher_files(&parsed_opts, argv + optind,
				   (uint32_t)(argc - optind), hash_ctx);
	else if (optind == argc)
		ret = hasher_checkfile(&parsed_opts, hash_ctx);
	else {
		fprintf(stderr, "-c cannot be used with input files\n");
		ret = 1;
	}

out:
	lc_hash_zero(hash_ctx);
	hasher_free_options(&parsed_opts);
	return ret;
}
