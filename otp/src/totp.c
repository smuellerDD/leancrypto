/*
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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
#include <time.h>

#include "lc_hotp.h"
#include "lc_totp.h"
#include "visibility.h"

/****************************************************************************
 * RFC 6238
 ****************************************************************************/
DSO_PUBLIC
int lc_totp(const uint8_t *hmac_key, size_t hmac_key_len, uint32_t step,
	    uint32_t digits, uint32_t *totp_val)
{
	time_t now;
	uint64_t counter;

	/* Get time in seconds since Epoch */
	now = time(NULL);
	if (now == (time_t)-1)
		return -errno;

	counter = (uint64_t)now;
	counter /= step;

	lc_hotp(hmac_key, hmac_key_len, counter, digits, totp_val);
	return 0;
}
