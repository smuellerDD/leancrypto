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

#include <dlfcn.h>
#include <errno.h>

#include "seeded_rng.h"
#include "seeded_rng_linux.h"
#include "ret_checkers.h"
#include "visibility.h"

/*
 * We link with ESDM at runtime as there is a cross-dependency between ESDM and
 * leancrypto: ESDM uses leancrypto algorithms and leancrypto uses ESDM as
 * entropy source.
 */
static void *esdm_rpc_client_handle = NULL;
static ssize_t (*esdm_rpcc_get_random_bytes_full)(uint8_t *buf, size_t buflen);
static void (*esdm_rpcc_fini_unpriv_service)(void);

/* Duplication from esdm_rpc_client.h */
#define esdm_invoke(x)                                                         \
	do {                                                                   \
		unsigned int __ctr = 0;                                        \
                                                                               \
		do {                                                           \
			ret = x;                                               \
		} while (ret == -EINTR && __ctr++ < 5);                        \
	} while (0)

int seeded_rng_noise_init(void)
{
	typedef int (*esdm_rpcc_interrupt_func_t)(void *interrupt_data);
	int (*esdm_rpcc_set_max_online_nodes)(uint32_t nodes);
	int (*esdm_rpcc_init_unpriv_service)(
		esdm_rpcc_interrupt_func_t interrupt_func);
	char *error;

	if (!esdm_rpc_client_handle) {
		esdm_rpc_client_handle = dlopen("libesdm_rpc_client.so.1",
						RTLD_LAZY);
	}

	/* If we have no success in opening the file, gracefully continue */
	if (!esdm_rpc_client_handle)
		return 0;

	dlerror();
	esdm_rpcc_set_max_online_nodes =
		(int (*)(uint32_t nodes)) dlsym(
			esdm_rpc_client_handle,
			"esdm_rpcc_set_max_online_nodes");
	error = dlerror();
	if (error != NULL)
		return -EOPNOTSUPP;

	esdm_rpcc_init_unpriv_service =
		(int (*)(esdm_rpcc_interrupt_func_t interrupt_func)) dlsym(
			esdm_rpc_client_handle,
			"esdm_rpcc_init_unpriv_service");
	error = dlerror();
	if (error != NULL)
		return -EOPNOTSUPP;

	esdm_rpcc_fini_unpriv_service =
		(void (*)(void)) dlsym(
			esdm_rpc_client_handle,
			"esdm_rpcc_fini_unpriv_service");
	error = dlerror();
	if (error != NULL)
		return -EOPNOTSUPP;

	esdm_rpcc_get_random_bytes_full =
		(ssize_t (*)(uint8_t *buf, size_t buflen)) dlsym(
			esdm_rpc_client_handle,
			"esdm_rpcc_get_random_bytes_full");
	error = dlerror();
	if (error != NULL)
		return -EOPNOTSUPP;

	esdm_rpcc_set_max_online_nodes(1);
	return esdm_rpcc_init_unpriv_service(NULL);
}

void seeded_rng_noise_fini(void)
{
	void *local_handle = esdm_rpc_client_handle;

	if (esdm_rpcc_fini_unpriv_service)
		esdm_rpcc_fini_unpriv_service();

	esdm_rpc_client_handle = NULL;
	esdm_rpcc_fini_unpriv_service = NULL;
	esdm_rpcc_get_random_bytes_full = NULL;

	if (local_handle)
		dlclose(local_handle);
}

ssize_t get_full_entropy(uint8_t *buffer, size_t bufferlen)
{
	ssize_t ret = 0;

	if (esdm_rpcc_get_random_bytes_full) {
		/* Reseed from ESDM without prediction resistance enabled. */
		esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer, bufferlen));
	}

	/*
	 * When ESDM was unsuccessful, revert to system native call. As the ESDM
	 * is intended for the Linux platform only, we can directly use the
	 * Linux entropy source as fallback.
	 */
	if (ret != (ssize_t)bufferlen)
		return getrandom_random(buffer, bufferlen);

	return ret ? ret : (ssize_t)bufferlen;
}
