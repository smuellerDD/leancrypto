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

#ifndef LC_INIT_H
#define LC_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

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
 * @param [in] flags currently unused
 *
 * @return 0 on success, < 0 on error
 */
int lc_init(unsigned int flags);

#ifdef __cplusplus
}
#endif

#endif /* LC_INIT_H */
