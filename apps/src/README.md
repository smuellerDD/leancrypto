# Leancrypto Applications

The following sections discuss the applications implemented and offered by leancrypto.

## sha*sum Applications

The following applications are drop-in replacements for the respective Linux coreutils applications with the same behavior and command line options:

* `sha256sum`

* `sha384sum`

* `sha512sum`

* `sha3-256sum`

* `sha3-384sum`

* `sha3-512sum`

## `ascon256-sum` Application

The `ascon256-sum` application is conceptually identical to the sha*sum applications above with the same command line options. Yet, it calculates an Ascon256 message digest.

## `lc_x509_generator`

The `lc_x509_generator` is the command line application providing an X.509 certificate generator and parser along with certificate validation. For details, see `asn1/src/README.md` section "X.509 Certificate Generator".

## `lc_pkcs7_generator`

The `lc_pkcs7_generator` is the command line application providing a PKCS#7 / CMS message generator and parser along with message validation and trust verification. For details, see `asn1/src/README.md` section "PKCS#7 Message Generator". This tool also is able to generate private keys encapsulated as PKCS#8 message.

## Secure Boot Signing Tools Supporting PQC

The `sbsign`, `sbverify`, `sbvarsign`, `sbsiglist`, `sbkeysync`, and `sbattach` tools are drop-in replacements for the respective tools provided with http://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git. They provide the same behavior and the same command line options as the originals. The key difference is that the created signatures are PQC signatures as supported by leancrypto:

* ML-DSA44, ML-DSA65, ML-DSA87

* SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128s,.SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256s,

* ML-DSA44/ED25519 hybrid, ML-DSA65/ED25519 hybrid

* ML-DSA87/ED448 hybrid

The signatures are calculated over PE/COFF executables and may be embedded into the executable. That supports Secure Boot following the [Windows Authenticode Portable Executable Signature Format](https://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/authenticode_pe.docx) as needed for the [shim bootloader](https://github.com/rhboot/shim).

The following difference to the original tools exist:

* Unlike OpenSSL, leancrypto's certificate parsing only supports one certificate per PEM file (OpenSSL supports multiple PEM-formatted certificate blobs in one file). Thus, if you have multiple additional certificates you want to provide with `--cert`, have one DER or PEM formatted certificate per file, but supply each file with a separate `--cert` option.
