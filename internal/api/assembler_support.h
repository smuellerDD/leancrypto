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

#ifndef ASSEMBLER_SUPPORT_H
#define ASSEMBLER_SUPPORT_H

// clang-format off

/******************************************************************************
 * Hardening macros
 ******************************************************************************/

/***************************** X86 64 CET Support *****************************/
#if defined __ELF__ && defined __CET__
# ifdef __x86_64__
#  define ASM_X86_MARK_CET_ALIGN 3
# else
#  define ASM_X86_MARK_CET_ALIGN 2
# endif
# define LC_ASM_END							       \
	.pushsection ".note.gnu.property", "a";				       \
	.p2align ASM_X86_MARK_CET_ALIGN;				       \
	.long 1f - 0f;							       \
	.long 4f - 1f;							       \
	.long 5;							       \
0:									       \
	.asciz "GNU";							       \
1:									       \
	.p2align ASM_X86_MARK_CET_ALIGN;				       \
	.long 0xc0000002;						       \
	.long 3f - 2f;							       \
2:									       \
	.long 3;							       \
3:									       \
	.p2align ASM_X86_MARK_CET_ALIGN;				       \
4:									       \
	.popsection
#endif

/*************************** ARM BTI / PAC Supprt *****************************/
/*
 * References:
 *  - https://community.arm.com/arm-community-blogs/b/architectures-and-processors-blog/posts/enabling-pac-and-bti-on-aarch64
 *  - https://developer.arm.com/documentation/101028/0012/5--Feature-test-macros
 *  - https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
 */
//TODO enable for Apple
#if (defined(__ELF__) && defined(__aarch64__))

/* BTI Support */
# if defined(__ARM_FEATURE_BTI_DEFAULT) && __ARM_FEATURE_BTI_DEFAULT == 1
#  define BTI_J bti j /* for jumps, IE br instructions */
#  define BTI_C bti c  /* for calls, IE bl instructions */
#  define GNU_PROPERTY_AARCH64_BTI 1 /* bit 0 GNU Notes is for BTI support */
# else
#  define BTI_J
#  define BTI_C
#  define GNU_PROPERTY_AARCH64_BTI 0
# endif

/* PAC Support */
# if defined(__ARM_FEATURE_PAC_DEFAULT)
#  if __ARM_FEATURE_PAC_DEFAULT & 1
#   define SIGN_LR paciasp /* sign with the A key */
#   define VERIFY_LR autiasp /* verify with the A key */
#  elif __ARM_FEATURE_PAC_DEFAULT & 2
#   define SIGN_LR pacibsp /* sign with the b key */
#   define VERIFY_LR autibsp /* verify with the b key */
#  endif
#  define GNU_PROPERTY_AARCH64_POINTER_AUTH 2 /* bit 1 GNU Notes is for PAC support */
# else
#  define SIGN_LR
#  define VERIFY_LR
#  define GNU_PROPERTY_AARCH64_POINTER_AUTH 0
# endif

/* Add the BTI / PAC support to GNU Notes section */
# if GNU_PROPERTY_AARCH64_BTI != 0 || GNU_PROPERTY_AARCH64_POINTER_AUTH != 0
#  define LC_ASM_END							       \
	.pushsection ".note.gnu.property", "a";				       \
	.balign 8;							       \
	.long 4;							       \
	.long 0x10;							       \
	.long 0x5;							       \
	.asciz "GNU";							       \
	.long 0xc0000000;						       \
	.long 4;							       \
	.long (GNU_PROPERTY_AARCH64_BTI|GNU_PROPERTY_AARCH64_POINTER_AUTH);    \
	.long 0;							       \
	.popsection
# endif
#endif

/****************************** Generic Helpers *******************************/

#ifdef LC_ASM_END
# ifdef __x86_64__
#  define LC_ASM_ENTER_HARDENING endbr64
# elif defined(__i386__)
#  define LC_ASM_ENTER_HARDENING endbr32
# elif defined (__aarch64__)
#  define LC_ASM_ENTER_HARDENING SIGN_LR
# else
#  define LC_ASM_ENTER_HARDENING
# endif

# ifdef __aarch64__
#  define LC_ASM_LEAVE_HARDENING VERIFY_LR ;
# else
#  define LC_ASM_LEAVE_HARDENING
# endif
#else /* LC_ASM_END */
# define LC_ASM_ENTER_HARDENING
# define LC_ASM_LEAVE_HARDENING
# define LC_ASM_END
#endif /* LC_ASM_END */

/******************************************************************************
 * Assembler support
 ******************************************************************************/

#ifdef LINUX_KERNEL

#include <linux/linkage.h>
#if __has_include(<linux/objtool.h>)
# include <linux/objtool.h>
#else
# define stack_frame_non_standard
#endif

#if __has_include(<asm/frame.h>)
# include <asm/frame.h>
#else
# define FRAME_START
# define FRAME_END
#endif

# define SYM_FUNC_ENTER(name)

# define SYM_FUNC(name)	name
# define SYM_TYPE_OBJ(name)						       \
	.type SYM_FUNC(name),%object

# define SYM_TYPE_FUNC(name)						       \
	.type SYM_FUNC(name),%function

# define SYM_SIZE(name)							       \
	.size SYM_FUNC(name),.-SYM_FUNC(name)

# ifndef SYM_FUNC_START
#  define SYM_FUNC_START(name)						       \
	.global SYM_FUNC(name) ;					       \
	SYM_FUNC(name):
# endif

# ifndef SYM_FUNC_END
#  define SYM_FUNC_END(name)						       \
	SYM_TYPE_FUNC(name) ;						       \
	SYM_SIZE(name)
# endif

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
	SYM_FUNC(name):							       \
	LC_ASM_ENTER_HARDENING ;

#  define SYM_FUNC_END(name)						       \
	SYM_TYPE_FUNC(name) ;						       \
	SYM_SIZE(name)

# elif (defined(__CYGWIN__) || defined(_WIN32))

#  define SYM_FUNC(name)	name

#  define SYM_TYPE_OBJ(name)						       \
	.type SYM_FUNC(name),%object

#  define SYM_TYPE_FUNC(name)

#  define SYM_SIZE(name)						       \
	.size SYM_FUNC(name),.-SYM_FUNC(name)

#  define SYM_FUNC_START(name)						       \
	.global SYM_FUNC(name) ;					       \
	SYM_FUNC(name):							       \
	LC_ASM_ENTER_HARDENING

#  define SYM_FUNC_ENTER(name)

#  define SYM_FUNC_END(name)

#  define FRAME_BEGIN

#  define FRAME_END

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
	SYM_FUNC(name):							       \
	LC_ASM_ENTER_HARDENING

#  define SYM_FUNC_ENTER(name)

#  define SYM_FUNC_END(name)						       \
	SYM_TYPE_FUNC(name) ;						       \
	SYM_SIZE(name)

#  define FRAME_BEGIN

#  define FRAME_END

# endif /* __APPLE__ */

# define RET								       \
	LC_ASM_LEAVE_HARDENING						       \
	ret

# define STACK_FRAME_NON_STANDARD # ignored

#endif /* LINUX_KERNEL */

// clang-format on

#endif /* ASSEMBLER_SUPPORT_H */
