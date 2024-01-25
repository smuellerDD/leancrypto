# Security Issues

The following list tries to enumerate all security issues on a best-effort
basis.

# Reporting Of Issues

If you detect any new security issues, please file a bug report or send
a private email to <smueller@chronox.de>.

## 2024-01-25

Integrate PQClean patch 3b43bc6fe46fe47be38f87af5019a7f1462ae6dd

* Kyber used division operations that might leak side-channel information.
[PR #534](https://github.com/PQClean/PQClean/pull/534) addressed this for the `clean` and `avx2` implementations.
