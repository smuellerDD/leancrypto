/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef ASSEMBLER_SUPPORT_H
#define ASSEMBLER_SUPPORT_H

#ifdef LINUX_KERNEL

#include <linux/linkage.h>
#include <linux/objtool.h>

# define SYM_FUNC_ENTER(name)

# define SYM_FUNC(name)	name
# define SYM_TYPE_OBJ(name)						       \
	.type SYM_FUNC(name),%object

# define SYM_TYPE_FUNC(name)						       \
	.type SYM_FUNC(name),%function

# define SYM_SIZE(name)							       \
	.size SYM_FUNC(name),.-SYM_FUNC(name)

#else /* LINUX_KERNEL */

# define ANNOTATE_INTRA_FUNCTION_CALL

# ifdef __APPLE__
#  define SYM_FUNC(name)	_##name
#  define SYM_TYPE_OBJ(name)
#  define SYM_TYPE_FUNC(name)
#  define SYM_SIZE(name)

/* The Apple assembler does not support command separation with ";" */
#  define SYM_FUNC_START(name)						       \
	.global SYM_FUNC(name)

#  define SYM_FUNC_ENTER(name)						       \
	SYM_FUNC(name):

# else /* __APPLE__ */
#  define SYM_FUNC(name)	name

#  define SYM_TYPE_OBJ(name)						       \
	.type SYM_FUNC(name),%object

#  define SYM_TYPE_FUNC(name)						       \
	.type SYM_FUNC(name),%function

#  define SYM_SIZE(name)						       \
	.size SYM_FUNC(name),.-SYM_FUNC(name)

#  define SYM_FUNC_START(name)						       \
	.hidden SYM_FUNC(name) ;					       \
	.global SYM_FUNC(name) ;					       \
	SYM_FUNC(name):

#  define SYM_FUNC_ENTER(name)

# endif

# define SYM_FUNC_END(name)						       \
	SYM_TYPE_FUNC(name) ;						       \
	SYM_SIZE(name)

# define RET	ret

# define STACK_FRAME_NON_STANDARD # ignored

# endif /* LINUX_KERNEL */

#endif /* ASSEMBLER_SUPPORT_H */
