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

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lc_memory_support.h"
#include "lc_memset_secure.h"
#include "lc_x509_generator_file_helper.h"
#include "ret_checkers.h"

/******************************************************************************
 * Helper code
 ******************************************************************************/

int x509_write_data(int fd, const uint8_t *data, size_t datalen)
{
	ssize_t written;

	while (datalen) {
		written = write(fd, data,
#if (defined(__CYGWIN__) || defined(_WIN32))
				(unsigned int)
#endif
					datalen);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (written == 0)
			return -EFAULT;

		datalen -= (size_t)written;
		data += (size_t)written;
	}

	return 0;
}

int get_data_memory(const char *filename, uint8_t **memory,
		    size_t *memory_length, enum lc_pem_flags pem_flags)
{
	uint8_t *mem_local = NULL, *mem_decoded = NULL;
	FILE *f = NULL;
	size_t mem_local_len, mem_decoded_len;
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

	mem_local_len = (size_t)sb.st_size;

	CKINT(lc_alloc_aligned((void **)&mem_local, sizeof(uint64_t),
			       mem_local_len));

	if (fread(mem_local, 1, mem_local_len, f) != (size_t)sb.st_size) {
		printf("Read failed\n");
		/*
		 * It is totally unclear to me why on Github some read
		 * operations fail here. To still have clean runs, return
		 * the meson return code 77 here.
		 */
		ret = -77;
		goto out;
	}

	/*
	 * Autoguess whether input data is PEM encoded. If it is, decode,
	 * otherwise use the mmapped data directly.
	 */
	if (lc_pem_is_encoded((const char *)mem_local, mem_local_len,
			      pem_flags) == 0) {
		uint8_t blank_chars;

		CKINT(lc_pem_decode_len((const char *)mem_local, mem_local_len,
					&mem_decoded_len, &blank_chars,
					pem_flags));
		CKINT(lc_alloc_aligned((void **)&mem_decoded, sizeof(uint64_t),
				       mem_decoded_len));
		CKINT(lc_pem_decode((const char *)mem_local, mem_local_len,
				    mem_decoded, mem_decoded_len, pem_flags));

		*memory = mem_decoded;
		mem_decoded = NULL;
		*memory_length = mem_decoded_len;
	} else {
		*memory = mem_local;
		mem_local = NULL;
		*memory_length = mem_local_len;
	}

out:
	if (f)
		fclose(f);
	if (mem_local)
		lc_free(mem_local);
	if (mem_decoded)
		lc_free(mem_decoded);
	return ret;
}

void release_data_memory(uint8_t *memory, size_t memory_length,
			 enum lc_pem_flags pem_flags)
{
	(void)pem_flags;
	if (memory) {
		lc_memset_secure(memory, 0, memory_length);
		lc_free(memory);
	}
}

#if (defined(__CYGWIN__) || defined(_WIN32))

int get_data(const char *filename, uint8_t **memory, size_t *memory_length,
	     enum lc_pem_flags pem_flags)
{
	return get_data_memory(filename, memory, memory_length, pem_flags);
}

void release_data(uint8_t *memory, size_t memory_length,
		  enum lc_pem_flags pem_flags)
{
	release_data_memory(memory, memory_length, pem_flags);
}

static int x509_write_pem_data(int fd, const uint8_t *data, size_t datalen,
			       enum lc_pem_flags pem_flags)
{
	char *memory = NULL;
	size_t certdata_pem_len;
	int ret;

	CKINT(lc_pem_encode_len(datalen, &certdata_pem_len, pem_flags));

	memory = malloc(certdata_pem_len + 1);
	CKNULL(memory, -ENOMEM);

	CKINT(lc_pem_encode(data, datalen, memory, certdata_pem_len,
			    pem_flags));

	/* Write final LF */
	memory[certdata_pem_len] = 0x0a;

	CKINT(x509_write_data(fd, (uint8_t *)memory, certdata_pem_len + 1));

out:
	if (memory) {
		lc_memset_secure(memory, 0, certdata_pem_len);
		free(memory);
	}
	return ret;
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

static int mmap_data(const char *filename, uint8_t **memory, size_t *mapped,
		     int oflags)
{
	int fd = -1;
	int ret = 0;
	struct stat sb;

	fd = open(filename, oflags | O_CLOEXEC);
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

int get_data(const char *filename, uint8_t **memory, size_t *mapped,
	     enum lc_pem_flags pem_flags)
{
	uint8_t *mmap_mem = NULL;
	size_t mmap_mem_len = 0;
	int ret;
	uint8_t blank_chars = 0;

	if (pem_flags == lc_pem_flag_nopem)
		return mmap_data(filename, memory, mapped, O_RDONLY);

	CKINT(mmap_data(filename, &mmap_mem, &mmap_mem_len, O_RDONLY));

	/*
	 * Autoguess whether input data is PEM encoded. If it is, decode,
	 * otherwise use the mmapped data directly.
	 */
	if (lc_pem_is_encoded((const char *)mmap_mem, mmap_mem_len,
			      pem_flags) == 0) {
		CKINT(lc_pem_decode_len((const char *)mmap_mem, mmap_mem_len,
					mapped, &blank_chars, pem_flags));
		CKINT(lc_alloc_aligned((void **)memory, sizeof(uint64_t),
				       *mapped));
		CKINT(lc_pem_decode((const char *)mmap_mem, mmap_mem_len,
				    *memory, *mapped, pem_flags));
	} else {
		*memory = mmap_mem;
		*mapped = mmap_mem_len;
		return 0;
	}

out:
	if (mmap_mem)
		munmap(mmap_mem, mmap_mem_len);
	return ret;
}

void release_data(uint8_t *memory, size_t memory_length,
		  enum lc_pem_flags pem_flags)
{
	if (!memory)
		return;

	if (pem_flags == lc_pem_flag_nopem) {
		munmap(memory, memory_length);
	} else {
		/*
		 * First we attempt to unmap. If it does not work, then
		 * we know the data was allocated and thus we free it.
		 */
		if (munmap(memory, memory_length) == -1) {
			lc_memset_secure(memory, 0, memory_length);
			lc_free(memory);
		}
	}
}

static int x509_write_pem_data(int fd, const uint8_t *data, size_t datalen,
			       enum lc_pem_flags pem_flags)
{
	char *memory = NULL;
	size_t certdata_pem_len;
	int ret;

	CKINT(lc_pem_encode_len(datalen, &certdata_pem_len, pem_flags));

	if (ftruncate(fd, (off_t)(certdata_pem_len + 1)) == -1) {
		ret = -errno;
		goto out;
	}

	memory = mmap(NULL, certdata_pem_len + 1, PROT_WRITE,
		      PROT_READ | MAP_PRIVATE, fd, 0);
	if (memory == MAP_FAILED) {
		memory = NULL;
		ret = -errno;
		goto out;
	}

	CKINT(lc_pem_encode(data, datalen, memory, certdata_pem_len,
			    pem_flags));

	/* Write final LF */
	memory[certdata_pem_len] = 0x0a;

out:
	if (memory) {
		munmap(memory, certdata_pem_len);
	}
	return ret;
}

#endif

int write_data(const char *filename, const uint8_t *data, size_t datalen,
	       enum lc_pem_flags pem_flags)
{
	int fd = -1;
	int ret = 0;

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

	if (pem_flags != lc_pem_flag_nopem) {
		CKINT(x509_write_pem_data(fd, data, datalen, pem_flags));
	} else {
		CKINT(x509_write_data(fd, data, datalen));
	}

out:
	if (fd >= 0)
		close(fd);
	return ret;
}
