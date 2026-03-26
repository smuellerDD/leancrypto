/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_INIT_H
#define LC_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Use the AES C implementation based on an S-Box
 *
 * This is a fast implementation, but not guaranteed to be constant time and
 * thus fully free of side-channels with respect to the plaintext or ciphertext.
 * Yet, the key schedule generation is using a constant-time operation.
 */
#define LC_INIT_AES_SBOX (1 << 0)

/**
 * Use the AES C implementation based on a constant time algorithm
 *
 * This is a slower implementation, but based on current understanding free
 * of side channels. Use ths if you need to rely on a C implementation of AES
 * and have extra requirements regarding security.
 *
 * Leancrypto applies a security-by-default strategy which implies that this
 * implementation is used as default if no accelerated implementations are
 * available. Yet, this implementation is about 3 to 5 times slower compared
 * to the AES with S-Boxes enabled with \p LC_INIT_AES_SBOX. If you are sure
 * that side-channels are of lesser concern in your environment and you use
 * the C implementation, you may use the S-Box variant.
 */
#define LC_INIT_AES_CT (1 << 1)

/**
 * @brief Initialization of leancrypto
 *
 * This function invokes all necessary initialization functions required at
 * the loading time of leancrypto. However, this function is only needed for
 * environments without a constructor functionality such as the Linux kernel
 * or the EFI environment.
 *
 * For regular environments such as Linux, this function is not required to be
 * called. But it does not hurt to be called.
 *
 * \note If this function is called, no other leancrypto service must be offered
 * as this function may alter the global leancrypto state.
 *
 * @param [in] flags see LC_INIT_* flags
 *
 * @return 0 on success, < 0 on error
 */
int lc_init(unsigned int flags);

#ifdef __cplusplus
}
#endif

#endif /* LC_INIT_H */
