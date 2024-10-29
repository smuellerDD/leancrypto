/*
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef HELPER_H
#define HELPER_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __not_used
#define __not_used __attribute__((__unused__))
#endif
#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif
#ifndef __always_inline
#define __always_inline __inline __attribute__((__always_inline__))
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef LINUX_KERNEL
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

/**
 * @brief Obtain pointer to data structure when having a pointer to one of
 *	  its members.
 *
 * Example:
 * struct foo *val = member_to_struct(&struct->list_entry, struct foo, list_entry);
 *
 * @param member the pointer to the member.
 * @param data_type the data type of the struct the member is part of.
 * @param member_var the member variable of the struct the member is
 *                   referenced with
 */
#define member_to_struct(member, data_type, member_var)                        \
	(data_type *)((char *)(member) - (char *)&((data_type *)0)->member_var)

/**
 * @brief Obtain size of a member of a data structure
 *
 * @param struct Data structure
 * @param member Member variable to obtain size from
 */
#define member_size(struct, member) (sizeof(((struct *)0)->member))

#ifdef __cplusplus
}
#endif

#endif /* HELPER_H */
