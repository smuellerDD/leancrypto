/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_STATUS_H
#define LC_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief (Re-)run the self tests
 *
 * If the self tests were already executed for a given algorithm, they are
 * triggered again.
 */
void lc_rerun_selftests(void);

/**
 * @brief Re-run the FIPS 140 integrity test
 *
 * \note This API is only present in the FIPS module instance of leancrypto.
 */
void lc_fips_integrity_checker(void);

/**
 * @brief Status information about leancrypto
 *
 * @param [in] outbuf Buffer to be filled with status information, allocated by
 *		      caller
 * @param [in] outlen Size of the output buffer
 */
void lc_status(char *outbuf, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* LC_STATUS_H */
