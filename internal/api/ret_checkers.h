/*
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
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
	_Pragma("GCC diagnostic push") _Pragma(                                \
                "GCC diagnostic ignored \"-Wpedantic\"")                       \
	printf("Error %d at %s:%s:%u\n", ret, __FILE__, __FUNCTION__, __LINE__);\
	_Pragma("GCC diagnostic pop")
#else
#define CKERROR_LOG
#endif

#define CKINT(x)                                                               \
	{                                                                      \
		ret = x;                                                       \
		if (ret < 0) {                                                 \
			CKERROR_LOG                                            \
			goto out;                                              \
		}                                                              \
	}

#define CKINT_LOG(x, ...)                                                      \
	{                                                                      \
		ret = x;                                                       \
		if (ret < 0) {                                                 \
			CKERROR_LOG                                            \
			printf(__VA_ARGS__);                                   \
			goto out;                                              \
		}                                                              \
	}

#define CKNULL(v, r)                                                           \
	{                                                                      \
		if (!v) {                                                      \
			ret = r;                                               \
			CKERROR_LOG                                            \
			goto out;                                              \
		}                                                              \
	}

#define CKNULL_LOG(v, r, ...)                                                  \
	{                                                                      \
		if (!v) {                                                      \
			printf(__VA_ARGS__);                                   \
			ret = r;                                               \
			CKERROR_LOG                                            \
			goto out;                                              \
		}                                                              \
	}

#ifdef __cplusplus
}
#endif

#endif /* RET_CHECKERS_H */
