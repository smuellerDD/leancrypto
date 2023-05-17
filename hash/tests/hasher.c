/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alignment.h"
#include "binhexbin.h"
#include "lc_sha256.h"
#include "lc_sha512.h"
#include "lc_sha3.h"
#include "lc_status.h"
#include "lc_memset_secure.h"
#include "ret_checkers.h"

static int check_filetype(int fd, struct stat *sb, const char *filename)
{
	int ret = fstat(fd, sb);
	if (ret) {
		fprintf(stderr, "fstat() failed: %s", strerror(errno));
		return -errno;
	}

	/* Do not return an error in case we cannot validate the data. */
	if ((sb->st_mode & S_IFMT) != S_IFREG &&
	    (sb->st_mode & S_IFMT) != S_IFLNK) {
		fprintf(stderr, "%s is no regular file or symlink", filename);
		return -EINVAL;
	}

	return 0;
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
		if ((*size - offset) < (off_t)*mapped )
			*mapped = (size_t)(*size - offset);
	} else {
		ret = check_filetype(fd, &sb, filename);
		if (ret)
			goto out;
		*size = sb.st_size;
		if (*size <= (off_t)*mapped) {
			*mapped = (size_t)*size;
		if (*size == 0)
			goto out;
		}
	}

	*memory = mmap(NULL, *mapped, PROT_READ, MAP_PRIVATE, fd, offset);
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

static int lc_hasher(const char *filename, struct lc_hash_ctx *hash_ctx)
{
	/* Mapping file in 16M segments */
	size_t mapped = 16<<20;
	off_t offset = 0, size = 0;
	ssize_t ret = 0;
	uint8_t *memblock = NULL;
	uint8_t *memblock_p;
	uint8_t md[64];

	lc_hash_init(hash_ctx);

	if (filename) {
		do {
			ret = mmap_file(filename, &memblock, &size, &mapped,
					offset);
			if (ret) {
				fprintf(stderr,
					"Use of mmap failed mapping %zu bytes at offset %" PRId64 " of file %s (%zd)\n",
					mapped, (int64_t)offset, filename, ret);
				return (int)ret;
			}
			/* Compute hash */
			memblock_p = memblock;
			size_t left = mapped;
			do {
				uint32_t todo = (left > INT_MAX) ?
						 INT_MAX : (uint32_t)left;

				lc_hash_update(hash_ctx, memblock_p, todo);
				left -= todo;
				memblock_p += todo;
			} while (left);
			munmap(memblock, mapped);
			offset = offset + (off_t)mapped;
		} while (offset ^ size);
	} else {
		uint8_t tmpbuf[1024] __align(32);
		uint32_t bufsize;

		while ((bufsize =
			(uint32_t)fread(tmpbuf, sizeof(uint8_t), sizeof(tmpbuf),
					stdin))) {

			lc_hash_update(hash_ctx, tmpbuf, bufsize);
		}
		lc_memset_secure(tmpbuf, 0, sizeof(tmpbuf));
	}

	lc_hash_final(hash_ctx, md);
	bin2print(md, lc_hash_digestsize(hash_ctx), stdout, "Message digest");
	return 0;
}

static void usage(void)
{
	char version[200];

	lc_status(version, sizeof(version));

	fprintf(stderr, "\nleancrypto library version: %s\n\n", version);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-h --hash <NAME>\t\tHash algorithm - supported:\n");
	fprintf(stderr, "\t\t\t\t[SHA2-256|SHA2-512|SHA3-256|SHA3-384|SHA3-512]\n");
	fprintf(stderr, "\t-f --file <file>\t\tFile to be hashed\n");
}

int main(int argc, char *argv[])
{
	const char *file = NULL;
	struct lc_hash_ctx *hash_ctx = NULL;
	LC_HASH_CTX_ON_STACK(hash_ctx_2_256, lc_sha256);
	LC_HASH_CTX_ON_STACK(hash_ctx_2_512, lc_sha512);
	LC_HASH_CTX_ON_STACK(hash_ctx_3_256, lc_sha3_256);
	LC_HASH_CTX_ON_STACK(hash_ctx_3_384, lc_sha3_384);
	LC_HASH_CTX_ON_STACK(hash_ctx_3_512, lc_sha3_512);

	int c = 0, ret;

	while (1) {
		int opt_index = 0;
		static struct option options[] = {
			{ "hash", required_argument, 0, 'h' },
			{ "file", required_argument, 0, 'f' },

			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "h:f:",
				options, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* hash */
				if (!strncmp(optarg, "SHA2-256", 7))
					hash_ctx = hash_ctx_2_256;
				else if (!strncmp(optarg, "SHA2-512", 7))
					hash_ctx = hash_ctx_2_512;
				else if (!strncmp(optarg, "SHA3-256", 7))
					hash_ctx = hash_ctx_3_256;
				else if (!strncmp(optarg, "SHA3-384", 7))
					hash_ctx = hash_ctx_3_384;
				else if (!strncmp(optarg, "SHA3-512", 7))
					hash_ctx = hash_ctx_3_512;
				else {
					fprintf(stderr,
						"Unknown hash algorith\n");
					ret = -EFAULT;
					goto out;
				}
				break;

			case 1:
				/* file */
				file = optarg;
				break;

			default:
				usage();
				ret = -EINVAL;
				goto out;
				break;
			}
			break;

		case 'h':
			if (!strncmp(optarg, "SHA2-256", 7))
				hash_ctx = hash_ctx_2_256;
			else if (!strncmp(optarg, "SHA2-512", 7))
				hash_ctx = hash_ctx_2_512;
			else if (!strncmp(optarg, "SHA3-256", 7))
				hash_ctx = hash_ctx_3_256;
			else if (!strncmp(optarg, "SHA3-384", 7))
				hash_ctx = hash_ctx_3_384;
			else if (!strncmp(optarg, "SHA3-512", 7))
				hash_ctx = hash_ctx_3_512;
			else {
				fprintf(stderr,
					"Unknown hash algorith\n");
				ret = -EFAULT;
				goto out;
			}
			break;
		case 'f':
			file = optarg;
			break;
		default:
			usage();
			ret = -EINVAL;
			goto out;
			break;
		}
	}

	ret = lc_hasher(file, hash_ctx);

out:
	lc_hash_zero(hash_ctx);
	return ret;
}
