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
#define LC_INTERFACE_FUNCTION(ret, symbol, param...)                           \
	ret symbol(param);                                                     \
	EXPORT_SYMBOL(symbol);                                                 \
	ret symbol(param)

#define LC_INIT_FUNCTION(ret, symbol, param...)                                \
	ret __init symbol(param);                                              \
	ret __init symbol(param)

#define LC_TEST_FUNC(ret, symbol, param...)                                    \
	static ret symbol(param);                                              \
	static int __init symbol##_init(void)                                  \
	{                                                                      \
		int __ret;                                                     \
                                                                               \
		pr_info("%s: Starting test case\n", KBUILD_MODNAME);           \
		__ret = symbol(0, NULL);                                       \
		pr_info("%s: Test case completed with return code %d\n",       \
			KBUILD_MODNAME, __ret);                                \
		return __ret ? -EFAULT : 0;                                    \
	}                                                                      \
	static void __exit symbol##_exit(void)                                 \
	{                                                                      \
	}                                                                      \
	module_init(symbol##_init);                                            \
	module_exit(symbol##_exit);                                            \
	MODULE_LICENSE("Dual BSD/GPL");                                        \
	MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");                \
	MODULE_DESCRIPTION("leancrypto test case");                            \
	static ret symbol(param)

#pragma GCC diagnostic pop

#define LC_INTERFACE_SYMBOL(ret, symbol)                                       \
	ret symbol;                                                            \
	EXPORT_SYMBOL(symbol);                                                 \
	ret symbol

#define LC_CONSTRUCTOR(_func)                                                  \
	void __init _func(void);                                               \
	void __init _func(void)

#else /* LINUX_KERNEL */

#define DSO_PUBLIC __attribute__((visibility("default")))
#define DSO_LOCAL __attribute__((visibility("hidden")))

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvariadic-macros"

#define LC_INTERFACE_FUNCTION(ret, symbol, param...)                           \
	DSO_PUBLIC ret symbol(param)

#define LC_INIT_FUNCTION(ret, symbol, param...) DSO_PUBLIC ret symbol(param)

#define LC_TEST_FUNC(ret, symbol, param...) ret symbol(param)

#pragma GCC diagnostic pop

#define LC_INTERFACE_SYMBOL(ret, symbol) DSO_PUBLIC ret symbol

#ifdef LC_EFI
/*
 * EFI does not have the constructor logic. Thus, mark the constructor functions
 * as regular non-static functions as they are intended to be called by lc_init.
 */
#define LC_CONSTRUCTOR(_func)                                                  \
	void _func(void);                                                      \
	void _func(void)
#else /* LC_EFI */

#define LC_CONSTRUCTOR_AUTOMATIC_AVAILABLE

#define LC_CONSTRUCTOR(_func)                                                  \
	static void __attribute__((constructor)) _func(void);                  \
	static void _func(void)
#endif /* LC_EFI */

#endif /* LINUX_KERNEL */

#endif /* VISIBILITY_H */
