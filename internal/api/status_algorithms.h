/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef STATUS_ALGORITHMS_H
#define STATUS_ALGORITHMS_H

#include "ext_headers_internal.h"
#include "lc_status.h"

#ifdef __cplusplus
extern "C" {
#endif

void alg_status_set_all_passed_state(void);
int lc_activate_library_selftest_init(int reinit);
void lc_activate_library_selftest_fini(void);
void lc_activate_library_internal(void);
void alg_status_set_result(enum lc_alg_status_result test_ret, uint64_t flag);
void alg_status_unset_result(uint64_t flag);
enum lc_alg_status_val alg_status(uint64_t algorithm);
void alg_status_unset_result_all(void);

enum lc_alg_status_result alg_status_get_result(uint64_t flag);

void alg_status_print(uint64_t flag, char *test_completed,
		      size_t test_completed_len, char *test_open,
		      size_t test_open_len, char *errorbuf,
		      size_t errorbuf_len);

#ifdef __cplusplus
}
#endif

#endif /* STATUS_ALGORITHMS_H */
