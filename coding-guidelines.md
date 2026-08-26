# Coding Guidelines

Code changes should follow these guidelines:

* KNF code format (use `addon/clang-format-helper.sh`)

	- no more than 80 characters per line

	- indentation with tabs (defined to be 8 characters in size)

* All externally visible symbols are prefixed with `lc_`.

* All externally visible macros are prefixed with `LC_`.

* All header files defining external APIs must have a name starting with `lc_` and cannot include internal header files.

* Ifdef's in the C code should be reduced to an absolute minimum. Conditional compilation is defined by the build environment. If a C file that can be conditionally compiled provides services to other C files, the associated header file shall contain ifdef'ed NOOP functions.
