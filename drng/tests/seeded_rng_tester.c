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
#include <stdio.h>
#include <string.h>

#include "lc_rng.h"
#include "memcmp_secure.h"
#include "ret_checkers.h"

static int seeded_rng_selftest(void)
{
	uint8_t act1[64], act2[sizeof(act1)];
	int ret;

	memset(act1, 0, sizeof(act1));
	memset(act2, 0, sizeof(act2));
	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, act1, sizeof(act1)));
	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, act2, sizeof(act2)));
	if (!memcmp_secure(act1, sizeof(act1), act2, sizeof(act2))) {
		printf("Seeded RNG produced identical data\n");
		return 1;
	}

out:
	return ret ? 1 : 0;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return seeded_rng_selftest();
}
