# (Re-)Generate `oid_registry_data.c`

The `oid_registry_data.c` file needs to be updated if new OIDs are added to
`oid_registry.h`. The following command is to be used to (re-)generated:

```
asn1/src/build_OID_registry asn1/src/oid_registry.h asn1/src/oid_registry_data.c

```

# (Re-)Generate C code from `*.asn1` Files

The different `*.asn1` files define the ASN.1 structure of different input data
files. They need to be converted into the corresponding C / H files to be
consumed during compilation. A (re-)generation is only needed if such `*.asn1`
file is updated. Perform the following steps to (re-)generate the C/H files:

1. Enable `asn1_compiler_enabled = true` in `asn1/src/meson.build`

2. Recompile the `leancrypto` library to get the ASN.1 compiler generated

3. (Re-)generate the C/H files from one given `*.asn1` file with the following
   command, assuming the build directory is found in `build` and the file to
   be converted is `asn1/src/x509.asn1`:

   ```
   build/asn1/src/asn1_compiler -v asn1/src/x509.asn1 asn1/src/x509.asn1.c asn1/src/x509.asn1.h
   ```

# X.509 Certificate Generator

The `leancrypto` library offers a X.509 certificate generator along with the
X.509 parser. This generator allows to generate PQC certificates using all
PQC algorithms offered by the library.

The generator is accessed by one of the following means:

* Use of the X.509 API offered with `lc_x509_generator.h`.

* Use of the X.509 generator application `lc_x509_generator` implemented in
  the `apps/src` directory.
  
The `lc_509_generator` application is to be considered a frontend to the API
which implies that the API implements all important operations with respect to
the generation.

The following sections outline `lc_509_generator` commands to obtain
certificates.

## Generate CA Certificate

The following command generates a new ML-DSA 87 key pair, generates a
self-signed CA certificate with all proper key usage flags, and stores the
following files:

* `ml-dsa87_cacert.der`: X.509 Root-CA certificate

* `ml-dsa87_cacert.privkey`: Raw ML-DSA 87 secret key

```
lc_x509_generator
  --keyusage digitalSignature
  --keyusage keyEncipherment
  --keyusage keyCertSign
  --keyusage critical
  --ca 
  --valid-from 1729527728
  --valid-to 2044210606
  --subject-cn "leancrypto test CA"
  --subject-ou "leancrypto test OU"
  --subject-o leancrypto
  --subject-st Saxony
  --subject-c DE
  --issuer-cn
  "leancrypto test CA"
  --issuer-ou "leancrypto test OU"
  --issuer-o leancrypto
  --issuer-st Saxony
  --issuer-c DE
  --serial 0102030405060708
  --skid 0a0b0c0d0e0f
  --akid 0a0b0c0d0e0f
  -o ml-dsa87_cacert.der
  --sk-file ml-dsa87_cacert.privkey
  --create-keypair ML-DSA87
```

The generated result looks like:

```
Serial Number: 01:02:03:04:05:06:07:08
Signature Algorithm: ML-DSA 87 SHA3-512
Issuer: C = DE, ST = Saxony, O = leancrypto, OU = leancrypto test OU, CN = leancrypto test CA
Subject: C = DE, ST = Saxony, O = leancrypto, OU = leancrypto test OU, CN = leancrypto test CA
Valid From: 2024-10-21 18:22:08
Valid To: 2034-10-11 22:16:46
Public Key Algorithm: ML-DSA87
X509v3 Subject Key Identifier: 0a:0b:0c:0d:0e:0f
X509v3 Authority Key Identifier: 0a:0b:0c:0d:0e:0f
X509v3 Basic Constraints: CA (critical)
X509v3 Key Usage: (critical) digitalSignature keyEncipherment keyCertSign 
AuthID[0] = 
AuthID[1] = 0a0b0c0d0e0f
AuthID[2] = 31633019060355040304126c65616e63727970746f20746573742043413011060355040a040a6c65616e63727970746f3009060355040604024445300d060355040804065361786f6e793019060355040b04126c65616e63727970746f2074657374204f55
X.509 ID = 010203040506070831633019060355040304126c65616e63727970746f20746573742043413011060355040a040a6c65616e63727970746f3009060355040604024445300d060355040804065361786f6e793019060355040b04126c65616e63727970746f2074657374204f55
Public key size 2592
Self-signed: yes
```

## Generate Intermediate 1 Certificate

The following command generates a new ML-DSA 65 key pair, generates an
intermediate certificate signed by the root certificate generated in section
[Generate CA Certificate], and stores the following files:

* `ml-dsa65_int1.der`: X.509 intermediate CA certificate

* `ml-dsa65_int1.privkey`: Raw ML-DSA 65 secret key

```
lc_x509_generator
  --keyusage digitalSignature
  --keyusage keyEncipherment
  --keyusage keyCertSign
  --keyusage critical
  --ca
  --valid-from 1729527728
  --valid-to 2044210606
  --subject-cn "leancrypto test int1"
  --subject-ou "leancrypto test OU"
  --subject-o leancrypto
  --subject-st Saxony
  --subject-c DE
  --serial 0203030405060708
  --skid 0b0c0d0e0f0001
  -o ml-dsa65_int1.der
  --sk-file ml-dsa65_int1.privkey
  --create-keypair ML-DSA65
  --x509-signer ml-dsa87_cacert.der
  --signer-sk-file ml-dsa87_cacert.privkey

```

The generated result looks like:

```
Serial Number: 02:03:03:04:05:06:07:08
Signature Algorithm: ML-DSA 87 SHA3-512
Issuer: C = DE, ST = Saxony, O = leancrypto, OU = leancrypto test OU, CN = leancrypto test CA
Subject: C = DE, ST = Saxony, O = leancrypto, OU = leancrypto test OU, CN = leancrypto test int1
Valid From: 2024-10-21 18:22:08
Valid To: 2034-10-11 22:16:46
Public Key Algorithm: ML-DSA65
X509v3 Subject Key Identifier: 0b:0c:0d:0e:0f:00:01
X509v3 Authority Key Identifier: 0a:0b:0c:0d:0e:0f
X509v3 Basic Constraints: CA (critical)
X509v3 Key Usage: (critical) digitalSignature keyEncipherment keyCertSign 
AuthID[0] = 
AuthID[1] = 0a0b0c0d0e0f
AuthID[2] = 31633019060355040304126c65616e63727970746f20746573742043413011060355040a040a6c65616e63727970746f3009060355040604024445300d060355040804065361786f6e793019060355040b04126c65616e63727970746f2074657374204f55
X.509 ID = 020303040506070831633019060355040304126c65616e63727970746f20746573742043413011060355040a040a6c65616e63727970746f3009060355040604024445300d060355040804065361786f6e793019060355040b04126c65616e63727970746f2074657374204f55
Public key size 1952
Self-signed: no
```

## Generate Intermediate 2 Certificate

The following command generates a new ML-DSA 44 key pair, generates an
intermediate certificate signed by the intermediate 1 certificate generated
in section [Generate Intermediate 1 Certificate], and stores the following
files:

* `ml-dsa44_int2.der`: X.509 intermediate CA certificate

* `ml-dsa44_int2.privkey`: Raw ML-DSA 44 secret key

```
lc_x509_generator 
  --keyusage digitalSignature
  --keyusage keyEncipherment
  --keyusage keyCertSign
  --keyusage critical
  --ca
  --valid-from 1729527728
  --valid-to 2044210606
  --subject-cn "leancrypto test int2"
  --subject-ou "leancrypto test OU"
  --subject-o leancrypto
  --subject-st Saxony
  --subject-c DE
  --serial 0303040506070809
  --skid 0c0d0e0f000102
  -o ml-dsa44_int2.der
  --sk-file ml-dsa44_int2.privkey
  --create-keypair ML-DSA44
  --x509-signer ml-dsa65_int1.der
  --signer-sk-file ml-dsa65_int1.privkey
```

The generated result looks like:

```
Serial Number: 03:03:04:05:06:07:08:09
Signature Algorithm: ML-DSA 65 SHA3-384
Issuer: C = DE, ST = Saxony, O = leancrypto, OU = leancrypto test OU, CN = leancrypto test int1
Subject: C = DE, ST = Saxony, O = leancrypto, OU = leancrypto test OU, CN = leancrypto test int2
Valid From: 2024-10-21 18:22:08
Valid To: 2034-10-11 22:16:46
Public Key Algorithm: ML-DSA44
X509v3 Subject Key Identifier: 0c:0d:0e:0f:00:01:02
X509v3 Authority Key Identifier: 0b:0c:0d:0e:0f:00:01
X509v3 Basic Constraints: CA (critical)
X509v3 Key Usage: (critical) digitalSignature keyEncipherment keyCertSign 
AuthID[0] = 
AuthID[1] = 0b0c0d0e0f0001
AuthID[2] = 3165301b060355040304146c65616e63727970746f207465737420696e74313011060355040a040a6c65616e63727970746f3009060355040604024445300d060355040804065361786f6e793019060355040b04126c65616e63727970746f2074657374204f55
X.509 ID = 03030405060708093165301b060355040304146c65616e63727970746f207465737420696e74313011060355040a040a6c65616e63727970746f3009060355040604024445300d060355040804065361786f6e793019060355040b04126c65616e63727970746f2074657374204f55
Public key size 1312
Self-signed: no
```

## Generate Leaf Certificate

The following command generates a new ML-DSA 87 key pair, generates a leaf
signed by the intermediate 2 certificate generated
in section [Generate Intermediate 2 Certificate], and stores the following
files:

* `ml-dsa87_leaf.der`: X.509 leaf certificate with usual key usage and EKU
  flags

* `ml-dsa87_leaf.privkey`: Raw ML-DSA 87 secret key

```
lc_x509_generator
  --keyusage dataEncipherment
  --keyusage critical
  --eku critical
  --eku serverAuth
  --eku codeSigning
  --valid-from 1729527728
  --valid-to 2044210606
  --subject-cn "leancrypto test leaf"
  --subject-ou "leancrypto test OU"
  --subject-o leancrypto
  --subject-st Saxony
  --subject-c DE
  --serial 0405060708090001
  --skid 0d0e0f00010203
  -o ml-dsa87_leaf.der
  --sk-file ml-dsa87_leaf.privkey
  --create-keypair ML-DSA87
  --x509-signer ml-dsa44_int2.der
  --signer-sk-file ml-dsa44_int2.privkey
```

The generated result looks like:

```
Serial Number: 04:05:06:07:08:09:00:01
Signature Algorithm: ML-DSA 44 SHA3-256
Issuer: C = DE, ST = Saxony, O = leancrypto, OU = leancrypto test OU, CN = leancrypto test int2
Subject: C = DE, ST = Saxony, O = leancrypto, OU = leancrypto test OU, CN = leancrypto test leaf
Valid From: 2024-10-21 18:22:08
Valid To: 2034-10-11 22:16:46
Public Key Algorithm: ML-DSA87
X509v3 Subject Key Identifier: 0d:0e:0f:00:01:02:03
X509v3 Authority Key Identifier: 0c:0d:0e:0f:00:01:02
X509v3 Key Usage: (critical) dataEncipherment 
X509v3 Extended Key Usage: (critical) ServerAuthentication CodeSigning 
AuthID[0] = 
AuthID[1] = 0c0d0e0f000102
AuthID[2] = 3165301b060355040304146c65616e63727970746f207465737420696e74323011060355040a040a6c65616e63727970746f3009060355040604024445300d060355040804065361786f6e793019060355040b04126c65616e63727970746f2074657374204f55
X.509 ID = 04050607080900013165301b060355040304146c65616e63727970746f207465737420696e74323011060355040a040a6c65616e63727970746f3009060355040604024445300d060355040804065361786f6e793019060355040b04126c65616e63727970746f2074657374204f55
Public key size 2592
Self-signed: no
```
