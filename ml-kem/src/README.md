# Code Structure

## C

All files in ml-kem/src/* are applicable.

This is a pure C implementation which may be adjusted depending on the following
statements.

If none of the architectures below are used, then:

Result: One implementation is present: C.

## RISCV64 ASM

Most files in ml-kem/src/* are applicable. Some functions are provided by
the proper header files from the riscv64/ directory.

Result: The "C" implementation actually becomes always accelerated with few
RISCV64 ASM operations.

## RISCV64 RVV with Vector Lengths 128 and 256

The RVV support actually contains 2 implementations: one for vector length 128
and one for vector length 256 (depending on the meson configuration). Each
implementation is separate and standalone in addition to the
aforementioned RISCV64 ASM implementation. At runtime, leancrypto automatically
selects whether ASM, RVV with vector length 128 or vector length 256 is used.

Result: 3 implementations are present: C/ASM, RVV vector length 128, and RVV
with vector length 256.

## ARMv7 ASM

Most files in ml-kem/src/* are applicable. Some functions are provided by
the proper header files from the armv7/ directory.

Result: The "C" implementation actually becomes always accelerated with few
ARMv7 ASM operations.

## ARMv8 ASM

The ARMv8 provides its own implementation in the armv8 directory. It uses
partially the C code from ml-kem/src/*. 

Result: The "C" implementation actually becomes always accelerated with few
ARMv7 ASM operations.

## AVX2

The AVX2 implementation is separate and standalone in addition to the C
implementation. At runtime, it is selected whether C or AVX2 is used.

Result: 2 implementations are present: C and AVX2.
