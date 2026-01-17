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

#include "binhexbin_raw.h"

static uint8_t bin_char(const char hex)
{
	if (48 <= hex && 57 >= hex)
		return (uint8_t)(hex - 48);
	if (65 <= hex && 70 >= hex)
		return (uint8_t)(hex - 55);
	if (97 <= hex && 102 >= hex)
		return (uint8_t)(hex - 87);
	return 0;
}

/*
 * Convert hex representation into binary string
 * @hex input buffer with hex representation
 * @hexlen length of hex
 * @bin output buffer with binary data
 * @binlen length of already allocated bin buffer (should be at least
 *	   half of hexlen -- if not, only a fraction of hexlen is converted)
 */
void lc_hex2bin(const char *hex, const size_t hexlen, uint8_t *bin,
		const size_t binlen)
{
	size_t i;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	/*
	 * handle odd-length of strings where the first digit is the least
	 * significant nibble
	 */
	if (hexlen & 1) {
		bin[0] = bin_char(hex[0]);
		bin++;
		hex++;
	}

	for (i = 0; i < chars; i++) {
		bin[i] = (uint8_t)(bin_char(hex[(i * 2)]) << 4);
		bin[i] |= bin_char(hex[((i * 2) + 1)]);
	}
}

#if 0
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
#else
static char hex_char(unsigned int bin, const int u)
{
	if (bin < 10)
		return (char)(bin + 0x30);
	else if (bin < 16)
		return (char)(bin + 0x57 - (unsigned int)(!!u * 0x20));

	return 0x78;
}
#endif

/*
 * Convert binary string into hex representation
 * @bin input buffer with binary data
 * @binlen length of bin
 * @hex output buffer to store hex data
 * @hexlen length of already allocated hex buffer (should be at least
 *	   twice binlen -- if not, only a fraction of binlen is converted)
 * @u case of hex characters (0=>lower case, 1=>upper case)
 */
void lc_bin2hex(const uint8_t *bin, const size_t binlen, char *hex,
		const size_t hexlen, const int u)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i * 2)] = hex_char((bin[i] >> 4), u);
		hex[((i * 2) + 1)] = hex_char((bin[i] & 0x0f), u);
	}
}
