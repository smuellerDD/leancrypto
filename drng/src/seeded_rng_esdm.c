/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include <esdm/esdm_rpc_client.h>
#include <errno.h>

#include "seeded_rng.h"
#include "seeded_rng_linux.h"
#include "ret_checkers.h"
#include "visibility.h"

int seeded_rng_noise_init(void)
{
	esdm_rpcc_set_max_online_nodes(1);
	return esdm_rpcc_init_unpriv_service(NULL);
}

void seeded_rng_noise_fini(void)
{
	esdm_rpcc_fini_unpriv_service();
}

ssize_t get_full_entropy(uint8_t *buffer, size_t bufferlen)
{
	ssize_t ret;

	esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer, bufferlen));

	/*
	 * When ESDM was unsuccessful, revert to system native call. As the ESDM
	 * is intended for the Linux platform only, we can directly use the
	 * Linux entropy source as fallback.
	 */
	if (ret != 0)
		return getrandom_random(buffer, bufferlen);

	return ret ? ret : (ssize_t)bufferlen;
}
