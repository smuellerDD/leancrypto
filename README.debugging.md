# Timecop - Finding Side Channels

Side channels is a recurring problem which can inadvertently leak sensitive data where the leak may be visible not just locally, but possibly also remotely. Thus, finding side channels based on sensitive data is important.

The leancrypto library has built-in support for finding side-channels (or the lack thereof) by marking memory holding sensitive data and using Valgrind to identify any possible side channels. The concept is summarized on the [Timecop](https://www.post-apocalyptic-crypto.org/timecop/) web page as follows:

Even though modern CPUs and operating systems have various methods to separate processes from one another, some side-channels can remain that allow attackers to extract information across process, CPU, or even network boundaries.

One such side-channel can open up when the execution time of a piece of code depends on secret data. This class of vulnerabilities has been used succesfully in the past to extract encryption keys from AES, private keys from RSA, and other kinds of attacks.

Timing side-channels can be hard to spot in the wild, but they can be detected automatically to some degree with dynamic analysis.

## How it works

Most timing side-channels are rooted in one of the following three causes:

* Conditional jumps based on secret data [1] e.g. if(key[i] == 0)

* Table lookups at secret indices [2], [3], [4], [5] e.g. s[i] = substitution_table[key[i]]

* Variable-time CPU instructions operating on secret data [6], e.g. key[i] / c
  On Intel Pentium 4, the number of cycles for a division instruction depends on the arguments.

Adam Langley described in 2010 how [the first two types can be detected automatically](https://www.imperialviolet.org/2010/04/01/ctgrind.html) using Valgrind.

Valgrind is a framework for dynamic code analysis that comes with a large range of tools for specific analysis tasks. One of those tools checks memory usage to identify memory leaks, use of uninitialized memory, read after free, and other common problems related to memory management.

When Valgrind checks for the use of uninitialized memory, it performs exactly the checks necessary to spot timing side-channels. By flagging secret data as uninitialized for Valgrind, it will report any cases where conditional jumps or table lookups are based on secret data.

## Limitations

Valgrind cannot spot cases where variable-time code is caused by variable-time CPU instructions.

## Testing Instructions

To perform such a side channel analysis, apply the following steps:

1. Configure leancrypto with the following option: `meson configure build -Dtimecop=enabled`

2. Compile the code

3. Execute different test cases with Valgrind as follows: `valgrind --track-origins=yes build/kem/tests/kyber_kem_tester_common`

4. A side channel is present if Valgrind reports an issue like the following where it reports a "Conditional jump or move depends on uninitialised value(s)" based on "Uninitialised value was created by a client request":

```
==13317== Conditional jump or move depends on uninitialised value(s)
==13317==    at 0x4851A2E: bcmp (in /usr/libexec/valgrind/vgpreload_memcheck-amd64-linux.so)
==13317==    by 0x10A86F: lc_compare (../internal/src/compare.c:52)
==13317==    by 0x10A6A8: _kmac_256_tester (../kmac/tests/kmac_256_tester.c:912)
==13317==    by 0x10A410: kmac_tester (../kmac/tests/kmac_256_tester.c:942)
==13317==    by 0x10A410: main (???:956)
==13317==  Uninitialised value was created by a client request
==13317==    at 0x48A0E7A: lc_kmac_init (../kmac/src/kmac.c:119)
==13317==    by 0x10A665: _kmac_256_tester (../kmac/tests/kmac_256_tester.c:909)
==13317==    by 0x10A410: kmac_tester (../kmac/tests/kmac_256_tester.c:942)
==13317==    by 0x10A410: main (???:956)
```

## References

[1] Onur Acıiçmez, Çetin Kaya Koç, Jean-Pierre Seifert, [Predicting secret keys via branch prediction](https://eprint.iacr.org/2006/288.pdf). In Proceedings of the 7th Cryptographers' Track at the RSA Conference on Topics in Cryptology

[2] Yuval Yarom, Katrina Falkner, [FLUSH+RELOAD: a High Resolution, Low Noise, L3 Cache Side-Channel Attack](https://eprint.iacr.org/2013/448.pdf).

[3] Daniel J. Bernstein, [Cache-timing attacks on AES](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf).

[4] Paul C. Kocher, [Timing Attacks in Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://link.springer.com/content/pdf/10.1007%2F3-540-68697-5_9.pdf).

[5] Mehmet Sinan İnci, Berk Gülmezoğlu, Gorka Irazoqui, Thomas Eisenbarth, Berk Sunar, [Seriously, get off my cloud! Cross-VM RSA Key Recovery in a Public Cloud](https://eprint.iacr.org/2015/898.pdf).

[6] Thierry Kaufmann, Hervé Pelletier, Serge Vaudenay, and Karine Villegas [When Constant-time Source Yields Variable-time Binary: Exploiting Curve25519-donna Built with MSVC 2015](https://infoscience.epfl.ch/record/223794/files/32_1.pdf).
