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

#ifndef LC_MEMSET_SECURE_H
#define LC_MEMSET_SECURE_H

#include "ext_headers.h"

/*
 * Tested following code:
 *
 * (1) __asm__ __volatile__("" : "=r" (s) : "0" (s));
 * (2) __asm__ __volatile__("": : :"memory");
 * (3) __asm__ __volatile__("" : "=r" (s) : "0" (s) : "memory");
 * (4) __asm__ __volatile__("" : : "r" (s) : "memory");
 *
 * Requred result:
 *
 * gcc -O3: objdump -d shows the following:
 *
 * 0000000000400440 <main>:
 * ...
 *   400469:       48 c7 04 24 00 00 00    movq   $0x0,(%rsp)
 *   400470:       00
 *   400471:       48 c7 44 24 08 00 00    movq   $0x0,0x8(%rsp)
 *   400478:       00 00
 *   40047a:       c7 44 24 10 00 00 00    movl   $0x0,0x10(%rsp)
 *   400481:       00
 *
 * clang -O3: objdump -d shows the following:
 *
 * 0000000000400590 <main>:
 * ...
 *   4005c3:       c7 44 24 10 00 00 00    movl   $0x0,0x10(%rsp)
 *   4005ca:       00
 *
 *
 * Test results:
 *
 * The following table marks an X when the aforementioned movq/movl code is
 * present (or an invocation of memset@plt) in the object code
 * (i.e. the code we want). Contrary, the table marks - where the code is not
 * present (i.e. the code we do not want):
 *
 *          | BARRIER  | (1) | (2) | (3) | (4)
 * ---------+----------+     |     |     |
 * Compiler |          |     |     |     |
 * =========+==========+=======================
 *                     |     |     |     |
 * gcc -O0             |  X  |  X  |  X  |  X
 *                     |     |     |     |
 * gcc -O2             |  -  |  X  |  X  |  X
 *                     |     |     |     |
 * gcc -O3             |  -  |  X  |  X  |  X
 *                     |     |     |     |
 * clang -00           |  X  |  X  |  X  |  X
 *                     |     |     |     |
 * clang -02           |  X  |  -  |  X  |  X
 *                     |     |     |     |
 * clang -03           |  -  |  -  |  X  |  X
 */

static inline void lc_memset_secure(void *s, int c, size_t n)
{
	memset(s, c, n);
	__asm__ __volatile__("" : : "r"(s) : "memory");
}

#if 0
#include <stdio.h>

int main(int argc, char *argv[])
{
	char buf[20];

	snprintf(buf, sizeof(buf) - 1, "test");
	printf("%s\n", buf);

	memset_secure(buf, 0, sizeof(buf));
	return 0;
}
#endif

#endif /* LC_MEMSET_SECURE_H */
