/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "lc_cshake256_drng.h"

struct opts {
	size_t bytecount;
	char *outfile;
	int hex;
};

static const char hex_char_map_l[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				       '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static const char hex_char_map_u[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				       '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static char hex_char(unsigned int bin, int u)
{
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

/*
 * Convert binary string into hex representation
 * @bin input buffer with binary data
 * @binlen length of bin
 * @hex output buffer to store hex data
 * @hexlen length of already allocated hex buffer (should be at least
 *	   twice binlen -- if not, only a fraction of binlen is converted)
 * @u case of hex characters (0=>lower case, 1=>upper case)
 */
static void bin2hex(const uint8_t *bin, const size_t binlen, char *hex,
		   const size_t hexlen, const int u)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i * 2)] = hex_char((bin[i] >> 4), u);
		hex[((i * 2) + 1)] = hex_char((bin[i] & 0x0f), u);
	}
}

static int cshake_drng(struct opts *opts, FILE *out)
{
	LC_CSHAKE256_DRNG_CTX_ON_STACK(cshake_ctx);
	struct timeval tv;
	uint64_t time;
	size_t bytes = opts->bytecount;
	uint8_t outbuf[LC_CSHAKE256_DRNG_MAX_CHUNK];

	if (gettimeofday(&tv, NULL) < 0) {
		printf("Cannot obtain timestamp: %s\n", strerror(errno));
		return 1;
	}
	time = (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;

	lc_cshake256_drng_seed(cshake_ctx, (uint8_t *)&time, sizeof(time),
			       NULL, 0);

	while (bytes) {
		size_t todo = (bytes > sizeof(outbuf) ? sizeof(outbuf) : bytes);

		lc_cshake256_drng_generate(cshake_ctx, NULL, 0, outbuf, todo);

		if (opts->hex) {
			char outhex[2 * LC_CSHAKE256_DRNG_MAX_CHUNK];

			bin2hex(outbuf, todo, outhex, sizeof(outhex), 0);
			fwrite(outhex, todo * 2, 1, out);
		} else {
			fwrite(outbuf, todo, 1, out);
		}

		bytes -= todo;
	}

	return 0;
}

int main(int argc, char *argv[])
{

	struct opts opts;
	FILE *out = stdout;
	int c = 0;


	opts.bytecount = 1000;
	opts.outfile = NULL;
	opts.hex = 0;

	while (1)
	{
		int opt_index = 0;
		static struct option options[] =
		{
			{"bytecount", 		required_argument,	0, 'b'},
			{"file", 		required_argument,	0, 'f'},
			{"hex", 		no_argument,		0, 'h'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "b:f:h", options, &opt_index);
		if (c == -1)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				opts.bytecount = strtoul(optarg, NULL, 10);
				if (opts.bytecount == ULONG_MAX)
					return EINVAL;
				break;
			case 1:
				opts.outfile = optarg;
				break;
			case 2:
				opts.hex = 1;
				break;
			}
			break;

		case 'b':
			opts.bytecount = strtoul(optarg, NULL, 10);
			if (opts.bytecount == ULONG_MAX)
				return EINVAL;
			break;
		case 'f':
			opts.outfile = optarg;
			break;
		case 'h':
			opts.hex = 1;
			break;
		default:
			return EINVAL;
		}
	}

	if (opts.outfile) {
		out = fopen(opts.outfile, "w");
		if (!out) {
			printf("Cannot open file %s: %s\n", opts.outfile, strerror(errno));
			return 1;
		}
	}

	return cshake_drng(&opts, out);
}
