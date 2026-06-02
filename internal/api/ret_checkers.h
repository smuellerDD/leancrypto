/*
 * Copyright (C) 2018 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef RET_CHECKERS_H
#define RET_CHECKERS_H

#ifdef __cplusplus
extern "C" {
#endif

//#define ret_t int __attribute__((warn_unused_result))

#ifdef LC_DEBUG
#define CKERROR_LOG                                                            \
	_Pragma("GCC diagnostic push")                                         \
		_Pragma("GCC diagnostic ignored \"-Wpedantic\"")               \
			printf("%s %d at %s:%s:%u\n",                          \
			       ret ? "Error" : "Return", ret, __FILE__,        \
			       __FUNCTION__, __LINE__);                        \
	_Pragma("GCC diagnostic pop")
#else
#define CKERROR_LOG
#endif

#ifdef LC_DEBUG
#define CKERROR_PURE_LOG                                                       \
	_Pragma("GCC diagnostic push")                                         \
		_Pragma("GCC diagnostic ignored \"-Wpedantic\"")               \
			printf("%s at %s:%s:%u\n", ret ? "Error" : "Return",   \
			       __FILE__, __FUNCTION__, __LINE__);              \
	_Pragma("GCC diagnostic pop")
#else
#define CKERROR_PURE_LOG
#endif

#define CKRET(cond, err)                                                       \
	do {                                                                   \
		if (cond) {                                                    \
			CKERROR_PURE_LOG                                       \
			ret = err;                                             \
			goto out;                                              \
		}                                                              \
	} while (0)

/*
 * Checker hardened against fault injections. The following faults are
 * countered:
 *
 * * Skipping of an instruction
 * * Modification of the condition
 *
 * This is achieved as follows:
 *
 * 1. use volatile return code variable to prevent compiler to remove redundant
 *    code.
 * 2. Initialize the variable that will hold the return code with non-zero value
 * 3. AND the condition onto the volatile variable - this step ensures that
 *    the initialized variable is used and set to zero.
 * 4. use positive and inverse check of the volatile return code
 * 5. only proceed if positive and inverse checks succeed
 *
 * @param [in] cond: Condition to check - 0 is success, != 0 is failure
 * @param [in] err: Return code if condition shows failure
 *
 * The following analysis has been conducted with -O3 and gcc 15.2.1
 *
 * //Analyze lc_ed25519_verify_internal
 *
 * // Use CKRET_HARDENED
 *
 *  // Load 0xffffffffffffffff into register x1
 *  264:   92800001        mov     x1, #0xffffffffffffffff         // #-1
 *  268:   aa1703e0        mov     x0, x23
 *  // Store register w1 onto stack at offset #48
 *  26c:   f9001be1        str     x1, [sp, #48]
 *  // Invoke ge25519_has_small_order - the core function for validation
 *  270:   94000000        bl      0 <ge25519_has_small_order>
 *  // Compare return code with 0x1
 *  274:   7100041f        cmp     w0, #0x1
 *  // Load x1 from stack at offset #48 - contains 0xffffffffffffffff
 *  278:   f9401be1        ldr     x1, [sp, #48]
 *  // Set property of x0 register
 *  27c:   9a9f17e0        cset    x0, eq  // eq = none
 *  // AND return code from function with x1 and store in x0
 *  280:   8a010000        and     x0, x0, x1
 *  // Store register w0 onto stack at offset #48
 *  284:   f9001be0        str     x0, [sp, #48]
 *  // Load register w0 from stack at offset #48
 *  288:   f9401be0        ldr     x0, [sp, #48]
 *  // Jump to error exit handler if value is not zero
 *  28c:   b5000a20        cbnz    x0, 3d0 <lc_ed25519_verify_internal+0x3d0>
 *  // Store register w0 onto stack at offset #48
 *  290:   f9401be0        ldr     x0, [sp, #48]
 *  // Add 1 to x0
 *  294:   91000400        add     x0, x0, #0x1
 *  // Store register w0 onto stack at offset #48
 *  298:   f9001be0        str     x0, [sp, #48]
 *  // Compare x0 with 0x1
 *  29c:   f100041f        cmp     x0, #0x1
 *  // Jump to error exit handler if value is not 0x1
 *  2a0:   54000981        b.ne    3d0 <lc_ed25519_verify_internal+0x3d0>  // b.any
 *  // Start of exit handler without error
 *  2a4:   4f00041f        movi    v31.4s, #0x0
 *
 * // check agaisnt unhardened operation
 *  // Invoke ge25519_has_small_order - central check for signaturevalidity
 *  3c4:   94000000        bl      0 <ge25519_has_small_order>
 *  // Set return code
 *  3c8:   12800928        mov     w8, #0xffffffb6                 // #-74
 *  // Compare return code of ge25519_has_small_order against 0x1
 *  3cc:   7100041f        cmp     w0, #0x1
 *  // Store positive result of comparison against 0x1 in w20
 *  3d0:   1a880294        csel    w20, w20, w8, eq        // eq = none
 *  // Jump to exit handler starting at 0x208 if negative result
 *  3d4:   17ffff8b        b       200 <lc_ed25519_verify_internal+0x200>
 *  // Continue with regular operation
 *  3d8:   90000002        adrp    x2, 0 <lc_ed25519_verify_internal>
 *  3dc:   91000042        add     x2, x2, #0x0
 *
 * Clang 22.1.5 shows a similar assembly output
 */
#define CKRET_HARDENED(cond, err)                                              \
	do {                                                                   \
		volatile unsigned long __hardened_ret = (unsigned long)-1;     \
		ret = err;                                                     \
		__hardened_ret &= ((unsigned long)cond);                       \
		if (__hardened_ret == 0) {                                     \
			if (!(++__hardened_ret != 1)) {                        \
				ret = 0;                                       \
				break;                                         \
			}                                                      \
		}                                                              \
		CKERROR_LOG                                                    \
		goto out;                                                      \
	} while (0)

/*
 * Hardened version of CKINT
 */
#define CKINT_HARDENED(cond)                                                   \
	do {                                                                   \
		ret = (cond);                                                  \
		CKRET_HARDENED(ret, ret);                                      \
	} while (0)
/*
 * Use this ret-checker for all int functions EXCEPT policy checkers (i.e.
 * function returning lc_x509_pol_ret_t - they must be handled with
 * CKINT_POL)!
 */
#define CKINT(x)                                                               \
	do {                                                                   \
		ret = (x);                                                     \
		if (ret < 0) {                                                 \
			CKERROR_LOG                                            \
			goto out;                                              \
		}                                                              \
	} while (0)

/*
 * Use this ret-checker with policy checkers (i.e. functions returning
 * lc_x509_pol_ret_t)
 */
#define CKINT_POL(x)                                                           \
	{                                                                      \
		ret_pol = x;                                                   \
		if (ret_pol < 0) {                                             \
			ret = ret_pol;                                         \
			goto out;                                              \
		} else if (ret_pol == LC_X509_POL_FALSE) {                     \
			ret = -EKEYREJECTED;                                   \
			goto out;                                              \
		}                                                              \
	}

#define CKINT_LOG(x, ...)                                                      \
	do {                                                                   \
		ret = (x);                                                     \
		if (ret < 0) {                                                 \
			CKERROR_LOG                                            \
			printf(__VA_ARGS__);                                   \
			goto out;                                              \
		}                                                              \
	} while (0)

#define CKNULL(v, r)                                                           \
	{                                                                      \
		if (!(v)) {                                                    \
			ret = (r);                                             \
			CKERROR_LOG                                            \
			goto out;                                              \
		}                                                              \
	}

#define CKNULL_LOG(v, r, ...)                                                  \
	do {                                                                   \
		if (!(v)) {                                                    \
			printf(__VA_ARGS__);                                   \
			ret = (r);                                             \
			CKERROR_LOG                                            \
			goto out;                                              \
		}                                                              \
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* RET_CHECKERS_H */
