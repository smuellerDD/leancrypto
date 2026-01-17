/* Hex/Bin converter
 *
 * Convert hex string into binary representation and vice versa
 *
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file
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
#include <stdlib.h>

#include "binhexbin.h"

/*
 * Allocate sufficient space for binary representation of hex
 * and convert hex into bin
 *
 * Caller must free bin
 * @hex input buffer with hex representation
 * @hexlen length of hex
 * @bin return value holding the pointer to the newly allocated buffer
 * @binlen return value holding the allocated size of bin
 *
 * return: 0 on success, !0 otherwise
 */
int hex2bin_alloc(const char *hex, const size_t hexlen, uint8_t **bin,
		  size_t *binlen)
{
	uint8_t *out = NULL;
	size_t outlen = 0;

	if (!hexlen)
		return -EINVAL;

	outlen = (hexlen + 1) / 2;

	out = calloc(1, outlen + 1);
	if (!out)
		return -errno;

	lc_hex2bin(hex, hexlen, out, outlen);
	*bin = out;
	*binlen = outlen;
	return 0;
}

/*
 * Allocate sufficient space for hex representation of bin
 * and convert bin into hex
 *
 * Caller must free hex
 * @bin input buffer with bin representation
 * @binlen length of bin
 * @hex return value holding the pointer to the newly allocated buffer
 * @hexlen return value holding the allocated size of hex
 *
 * return: 0 on success, !0 otherwise
 */
int bin2hex_alloc(const uint8_t *bin, const size_t binlen, char **hex,
		  size_t *hexlen)
{
	char *out = NULL;
	size_t outlen = 0;

	if (!binlen)
		return -EINVAL;

	outlen = (binlen) * 2;

	out = calloc(1, outlen + 1);
	if (!out)
		return -errno;

	lc_bin2hex(bin, binlen, out, outlen, 0);
	*hex = out;
	*hexlen = outlen;
	return 0;
}

void bin2print(const unsigned char *bin, const size_t binlen, FILE *out,
	       const char *explanation)
{
	char *hex = NULL;
	size_t hexlen = binlen * 2 + 1;

	if (!bin)
		return;

	if (binlen) {
		hex = calloc(1, hexlen);
		if (!hex)
			return;
		lc_bin2hex(bin, binlen, hex, hexlen - 1, 0);
	}
	if (explanation)
		fprintf(out, "%s = ", explanation);

	fprintf(out, "%s\n", (hex) ? hex : "");
	free(hex);
}

static int _bin2hex_html(const unsigned char *str, size_t strlen, char *html,
			 size_t htmllen, size_t *reqlen, const char *unreserved,
			 size_t unreservedlen)
{
	while (strlen) {
		unsigned int charbytes;
		unsigned int hexbytes;
		unsigned int i;
		unsigned int is_unreserved = 0;

		if ((*str & ~0x7f) == 0)
			charbytes = 1;
		else if ((*str & ~0x1f) == 0xc0)
			charbytes = 2;
		else if ((*str & ~0xf) == 0xe0)
			charbytes = 3;
		else if ((*str & ~7) == 0xf0)
			charbytes = 4;
		else
			return -EINVAL;

		if (charbytes == 1) {
			for (i = 0; i < unreservedlen; i++) {
				if (*str == unreserved[i]) {
					is_unreserved = 1;
					break;
				}
			}
		}

		/*
		 * For non-unreserved characters each byte has to be
		 * pre-pended with a percent sign.
		 */
		if (!is_unreserved)
			hexbytes = charbytes * 3;
		else
			hexbytes = charbytes;

		/* We only count the number of bytes */
		if (reqlen) {
			*reqlen += hexbytes;
			strlen -= charbytes;
			str += charbytes;
			continue;
		}

		/* ensure we have sufficient space */
		if (hexbytes >= htmllen)
			return -ENOMEM;
		if (charbytes > strlen)
			return -ENOMEM;

		/*
		 * Operate byte-wise: add "%" followed by a one-character
		 * bin2hex.
		 */
		for (i = 0; i < charbytes; i++) {
			if (!is_unreserved) {
				*html = '%';
				html++;
				htmllen--;

				lc_bin2hex(str, 1, html, htmllen, 1);
				str++;
				strlen--;
				html += 2;
				htmllen -= 2;
			} else {
				/* Simply copy unreserved to destination */
				*html = (char)*str;
				str++;
				strlen--;
				html++;
				htmllen--;
			}
		}
	}

	/* Ensure we have a trailing NULL terminator */
	if (reqlen) {
		*reqlen += 1;
	} else {
		*html = '\0';
	}

	return 0;
}

/*
 * Characters that do not need to be converted as per RFC 3986
 * section 2.3
 */
static const char unreserved[] = "abcdefghijklmnopqrstuvwxyz"
				 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				 "0123456789"
				 "-._~";

/* Keep URL key characters */
static const char unreserved_url[] =
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"0123456789"
	"-._~"
	":=[]?&%"; /* Do not convert search helper */

int bin2hex_html(const char *str, size_t strlen, char *html,
		 const size_t htmllen)
{
	return _bin2hex_html((const unsigned char *)str, strlen, html, htmllen,
			     NULL, unreserved, sizeof(unreserved) - 1);
}

int bin2hex_html_from_url(const char *str, const size_t strlen, char *html,
			  const size_t htmllen)
{
	return _bin2hex_html((const unsigned char *)str, strlen, html, htmllen,
			     NULL, unreserved_url, sizeof(unreserved_url) - 1);
}

int bin2hex_html_alloc(const char *str, const size_t strlen, char **html,
		       size_t *htmllen)
{
	size_t outlen = 0;
	char *out = NULL;
	int ret;

	if (!strlen)
		return -EINVAL;

	ret = _bin2hex_html((const unsigned char *)str, strlen, NULL, 0,
			    &outlen, unreserved, sizeof(unreserved) - 1);
	if (ret)
		return ret;

	out = calloc(1, outlen + 1);
	if (!out)
		return -errno;

	ret = _bin2hex_html((const unsigned char *)str, strlen, out, outlen,
			    NULL, unreserved, sizeof(unreserved) - 1);
	if (ret) {
		free(out);
		return ret;
	}

	*html = out;
	*htmllen = outlen;

	return 0;
}
