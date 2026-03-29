# Security Issues

The following list tries to enumerate all security issues on a best-effort
basis.

# Reporting Of Issues

If you detect any new security issues, please file a bug report or send
a private email to <smueller@chronox.de>.

## 2026-03-29

X.509 Subject parser: Overflow in size parser of a subject name component

* With this, an attacker can craft a certificate where only a sub-part of a name
  component is matched instead of the full component string. Therefore an
  impersonation with a wrongly crafted certificate that has a valid signature is
  possible.

* Credits: Sunwoo Lee and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH).

## 2024-06-03

Integrate https://github.com/pq-crystals/kyber patch
0264efacf18dd665d2066f21df3a3290b52ba240

* Fixed secret-dependent branch in poly_frommsg introduced by recent
  versions of clang with some flags (Thanks to Antoon Purnal for pointing
  this out!)

## 2024-01-25

Integrate PQClean patch 3b43bc6fe46fe47be38f87af5019a7f1462ae6dd

* Kyber used division operations that might leak side-channel information.
[PR #534](https://github.com/PQClean/PQClean/pull/534) addressed this for the `clean` and `avx2` implementations.
