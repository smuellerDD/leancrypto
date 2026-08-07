/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_EXPORT_H
#define LC_EXPORT_H

/*
 * Windows requires the consumer of a DLL to reference exported *data* symbols
 * through the import table. For function symbols the linker transparently
 * generates a call thunk which is why they need no annotation. For data
 * symbols no such indirection exists - without __declspec(dllimport) the
 * reference is bound to the address of the (bogus) thunk the import library
 * carries instead of to the variable itself, and the consumer operates on
 * garbage at runtime.
 *
 * Therefore all data symbols defined with LC_INTERFACE_SYMBOL are exported as
 * DATA in leancrypto.def and are declared with LC_DLL_IMPORT here.
 *
 * LC_LINK_SHARED is added to the compiler flags of everybody linking against
 * the leancrypto DLL - see the leancrypto dependency object in meson.build and
 * the Cflags of the generated pkg-config file. It is deliberately not set when
 * leancrypto itself is compiled, nor when a consumer links against the static
 * library, because in both cases the symbols are resolved directly.
 *
 * On all other systems the macro is empty.
 */
#if defined(LC_LINK_SHARED) && (defined(_WIN32) || defined(__CYGWIN__))
#define LC_DLL_IMPORT __declspec(dllimport)
#else
#define LC_DLL_IMPORT
#endif

#endif /* LC_EXPORT_H */
