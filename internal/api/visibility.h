/*
 *  see https://gcc.gnu.org/wiki/Visibility
 *
 *  use -fvisibility=hidden to mark all symbols hidden per default
 *
 *  It is sufficient to use the macros in the declarations only. The
 *  definitions do not need to be instrumented.
 */

#ifndef VISIBILITY_H
#define VISIBILITY_H

#ifdef LINUX_KERNEL

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvariadic-macros"
#define LC_INTERFACE_FUNCTION(ret, symbol, param...)			       \
	ret symbol(param);						       \
	EXPORT_SYMBOL(symbol);						       \
	ret symbol(param)

#define LC_TEST_FUNC(ret, symbol, param...)				       \
	static __maybe_unused ret symbol(param)

#pragma GCC diagnostic pop

#define LC_INTERFACE_SYMBOL(ret, symbol)				       \
	ret symbol;							       \
	EXPORT_SYMBOL(symbol);						       \
	ret symbol

#else /* LINUX_KERNEL */

#define DSO_PUBLIC __attribute__ ((visibility ("default")))
#define DSO_LOCAL  __attribute__ ((visibility ("hidden")))

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvariadic-macros"

#define LC_INTERFACE_FUNCTION(ret, symbol, param...)			       \
	DSO_PUBLIC ret symbol(param)

#define LC_TEST_FUNC(ret, symbol, param...)				       \
	ret symbol(param)

#pragma GCC diagnostic pop

#define LC_INTERFACE_SYMBOL(ret, symbol)				       \
	DSO_PUBLIC ret symbol

#endif /* LINUX_KERNEL */

#endif /* VISIBILITY_H */
