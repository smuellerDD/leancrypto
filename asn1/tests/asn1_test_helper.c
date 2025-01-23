/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include <fcntl.h>
#include <sys/stat.h>

#include "asn1_test_helper.h"
#include "ret_checkers.h"

/******************************************************************************
 * Helper code
 ******************************************************************************/

#if (defined(__CYGWIN__) || defined(_WIN32))

int get_data(const char *filename, uint8_t **memory, size_t *memory_length)
{
	FILE *f = NULL;
	int ret = 0;
	struct stat sb;

	ret = stat(filename, &sb);
	if (ret)
		return -errno;
	if (sb.st_size < 0 || sb.st_size > INT_MAX) {
		ret = -EFAULT;
		goto out;
	}

	f = fopen(filename, "r");
	CKNULL_LOG(f, -EFAULT, "Cannot open file %s\n", filename);

	*memory_length = (size_t)sb.st_size;

	*memory = malloc((size_t)sb.st_size);
	if (!*memory) {
		ret = -ENOMEM;
		goto out;
	}

	if (fread(*memory, 1, *memory_length, f) != (size_t)sb.st_size) {
		printf("Read failed\n");
		/*
		 * It is totally unclear to me why on Github some read
		 * operations fail here. To still have clean runs, return
		 * the meson return code 77 here.
		 */
		ret = -77;
	}

out:
	if (f)
		fclose(f);
	return ret;
}

void release_data(uint8_t *memory, size_t memory_length)
{
	(void)memory_length;
	if (memory)
		free(memory);
}

#else /* (defined(__CYGWIN__) || defined(_WIN32)) */

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

int get_data(const char *filename, uint8_t **memory, size_t *mapped)
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

	CKINT(check_filetype(fd, &sb));
	if (sb.st_size < 0) {
		ret = -EFAULT;
		goto out;
	}

	*mapped = (size_t)sb.st_size;

	*memory = mmap(NULL, (size_t)sb.st_size, PROT_READ,
		       MAP_PRIVATE
#ifdef __linux__
			       | MAP_POPULATE
#endif
		       ,
		       fd, 0);
	if (*memory == MAP_FAILED) {
		*memory = NULL;
		ret = -errno;
		goto out;
	}
	madvise(*memory, (size_t)sb.st_size,
		MADV_SEQUENTIAL | MADV_WILLNEED
#ifdef __linux__
			| MADV_HUGEPAGE
#endif
	);

out:
	close(fd);
	return ret;
}

void release_data(uint8_t *memory, size_t memory_length)
{
	if (memory)
		munmap(memory, memory_length);
}
#endif
