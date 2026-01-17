/* UUID generation following RFC4122
 *
 * Copyright (C) 2021, Stephan Mueller <smueller@chronox.de>
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

#include "binhexbin.h"
#include "conv_be_le.h"
#include "ext_headers_internal.h"
#include "lc_rng.h"
#include "lc_uuid.h"
#include "ret_checkers.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(void, lc_uuid_bin2hex, const uint8_t uuid[16],
		      char uuid_str[37])
{
	bin2hex(uuid, 4, uuid_str, 8, 0);
	uuid_str[8] = '-';

	bin2hex(uuid + 4, 2, uuid_str + 9, 4, 0);
	uuid_str[13] = '-';

	bin2hex(uuid + 6, 2, uuid_str + 14, 4, 0);
	uuid_str[18] = '-';

	bin2hex(uuid + 8, 2, uuid_str + 19, 4, 0);
	uuid_str[23] = '-';

	bin2hex(uuid + 10, 6, uuid_str + 24, 12, 0);

	uuid_str[36] = '\0';
}

LC_INTERFACE_FUNCTION(int, lc_uuid_hex2bin, const char *uuid_str,
		      size_t uuid_strlen, uint8_t uuid[16])
{
	if (uuid_strlen < 36)
		return -EINVAL;

	hex2bin(uuid_str, 8, uuid, 4);
	if (uuid_str[8] != 0x2d)
		return -EINVAL;

	hex2bin(uuid_str + 9, 4, uuid + 4, 2);
	if (uuid_str[13] != 0x2d)
		return -EINVAL;

	hex2bin(uuid_str + 14, 4, uuid + 6, 2);
	if (uuid_str[18] != 0x2d)
		return -EINVAL;

	hex2bin(uuid_str + 19, 4, uuid + 8, 2);
	if (uuid_str[18] != 0x2d)
		return -EINVAL;

	hex2bin(uuid_str + 24, 12, uuid + 10, 6);

	return 0;
}

/******************************************************************************/

LC_INTERFACE_FUNCTION(int, lc_uuid_random, char uuid_str[37])
{
#ifdef LC_DRNG_PRESENT
	uint8_t uuid[16];

        lc_rng_generate(lc_seeded_rng, (uint8_t *)"random UUID", 11, uuid,
		       	sizeof(uuid));

	/* UUID version is set to 4 denominating a random generation */
	uuid[6] = (uint8_t)((uuid[6] & 0x0F) | 0x40);
	uuid[8] = (uint8_t)((uuid[8] & 0x3F) | 0x80);

	lc_uuid_bin2hex(uuid, uuid_str);

	return 0;
#else
	(void)uuid_str;
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_uuid_time, char uuid_str[37], uint64_t node)
{
	time64_t time_since_epoch, n_sec = 0;

	if (!lc_get_time(&time_since_epoch, &n_sec)) {
		union {
			uint64_t uuid64[2];
			uint8_t uuid8[16];
		} u;

		/* Time stamp */
		u.uuid64[0] = ((uint64_t)time_since_epoch & 0xFFFFFFFF) * 1000000000UL;
		u.uuid64[0] = u.uuid64[0] + (uint64_t)n_sec;
		u.uuid64[0] = be_bswap64(u.uuid64[0]);

		/* UUID version is set to 4 denominating a random generation */
		u.uuid8[6] = (u.uuid8[6] & 0x0F) | 0x10;
		u.uuid8[8] = (u.uuid8[8] & 0x3F) | 0x80;

		/* Node ID: provided by caller */
		u.uuid64[1] = node;

		lc_uuid_bin2hex(u.uuid8, uuid_str);
	} else {
		return lc_uuid_random(uuid_str);
	}

	return 0;
}
