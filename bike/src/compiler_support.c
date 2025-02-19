/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
/*
 * This code is derived in parts from the LLVM project (Apache License v2.0).
 *
 * The only reason why this code is duplicated is the fact that the compiler
 * automatically creates stubs for these functions and there is no compiler
 * library present in the kernel. Thus, the functions used by leancrypto are
 * extracted - I wished this would not have been necessary.
 */

/*
 * This function is required for the Linux kernel - in user space it is provided
 * by the compiler library.
 */

int __popcountdi2(unsigned long a);
int __popcountdi2(unsigned long a)
{
	unsigned long long x2 = (unsigned long long)a;

	x2 = x2 - ((x2 >> 1) & 0x5555555555555555uLL);
	// Every 2 bits holds the sum of every pair of bits (32)
	x2 = ((x2 >> 2) & 0x3333333333333333uLL) + (x2 & 0x3333333333333333uLL);
	// Every 4 bits holds the sum of every 4-set of bits (3 significant bits) (16)
	x2 = (x2 + (x2 >> 4)) & 0x0F0F0F0F0F0F0F0FuLL;
	// Every 8 bits holds the sum of every 8-set of bits (4 significant bits) (8)

	unsigned int x = (x2 + (x2 >> 32));

	// The lower 32 bits hold four 16 bit sums (5 significant bits).
	//   Upper 32 bits are garbage
	x = x + (x >> 16);
	// The lower 16 bits hold two 32 bit sums (6 significant bits).
	//   Upper 16 bits are garbage
	return (x + (x >> 8)) & 0x0000007F; // (7 significant bits)
}

int __popcountsi2(unsigned int a);
int __popcountsi2(unsigned int a)
{
	unsigned int x = a;

	x = x - ((x >> 1) & 0x55555555);
	// Every 2 bits holds the sum of every pair of bits
	x = ((x >> 2) & 0x33333333) + (x & 0x33333333);
	// Every 4 bits holds the sum of every 4-set of bits (3 significant bits)
	x = (x + (x >> 4)) & 0x0F0F0F0F;
	// Every 8 bits holds the sum of every 8-set of bits (4 significant bits)
	x = (x + (x >> 16));
	// The lower 16 bits hold two 8 bit sums (5 significant bits).
	//    Upper 16 bits are garbage
	return (x + (x >> 8)) & 0x0000003F; // (6 significant bits)
}
