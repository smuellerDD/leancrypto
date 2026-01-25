# (Re-)Generate `oid_registry_data.c`

The `oid_registry_data.c` file needs to be updated if new OIDs are added to
`lc_asn1.h`. The following command is to be used to (re-)generated:

```
asn1/src/build_OID_registry asn1/api/lc_asn1.h asn1/src/oid_registry_data.c

```

# (Re-)Generate C code from `*_asn1` Files

The different `*_asn1` files define the ASN.1 structure of different input data
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
  --issuer-cn "leancrypto test CA"
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
Signature Algorithm: ML-DSA 87 <builtin>
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
Signature Algorithm: ML-DSA 87 <builtin>
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
Signature Algorithm: ML-DSA 65 <builtin>
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
Signature Algorithm: ML-DSA 44 <builtin>
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
# PKCS#7 Message Generator

The `leancrypto` library offers a PKCS#7 message generator along with the
PKCS#7 parser. This generator allows to generate PQC certificates using all
PQC algorithms offered by the library.

The generator is accessed by one of the following means:

* Use of the PKCS#7 API offered with `lc_pkcs7_generator.h`.

* Use of the PKCS#7 generator application `lc_pkcs7_generator` implemented in
  the `apps/src` directory.
  
The `lc_pkcs7_generator` application is to be considered a frontend to the API
which implies that the API implements all important operations with respect to
the generation.

The following sections outline `lc_pkcs7_generator` commands to obtain
such messages.

## Generate PKCS#7 Message with 4-way Certificate Chain

The following command uses X.509 certificates and keys generated in the
preceding sections:

1. generates a PKCS#7 message `ml-dsa.p7b`

2. signs the data found in the file `ml-dsa87_cacert.der` - this can be any file with any data that shall be signed

3. signs with the signer X.509 certificate `ml-dsa87_leaf.der` and its
   associated private key `ml-dsa87_leaf.privkey`
   
4. adds the signer certificate, and the 3 CA certificates of
   `ml-dsa44_int2.der`, `ml-dsa65_int1.der`, and the root CA certificate
   `ml-dsa87_cacert.der` (the root or the intermediate certificates are not
   needed, provided they are present in the trust store during later
   verification)

5. verifies the PKCS#7 message against a trust store holding the root
   CA certificate `ml-dsa87_cacert.der`

The command generates:

* `ml-dsa.p7b`: PKCS#7 message

```
lc_pkcs7_generator
  -o ml-dsa.p7b 
  -i ml-dsa87_cacert.der
  --x509-signer ml-dsa87_leaf.der
  --signer-sk-file ml-dsa87_leaf.privkey
  --x509-cert ml-dsa44_int2.der
  --x509-cert ml-dsa65_int1.der
  --x509-cert ml-dsa87_cacert.der
  --trust-anchor ml-dsa87_cacert.der
```

## Verify PKCS#7 Message with 4-way Certificate Chain

The following command verifies the PKCS#7 message generated in section
[Generate PKCS#7 Message with 4-way Certificate Chain]. It uses

* the data in the file in the file `ml-dsa87_cacert.der` that was signed 

* the PKCS#7 message in `ml-dsa.p7b`

* using the trust anchor `ml-dsa87_cacert.der`

```
lc_pkcs7_generator
  --print-pkcs7 ml-dsa.p7b
  -i ml-dsa87_cacert.der
  --trust-anchor ml-dsa87_cacert.der
```

The command should return without an error. The command also prints out the
PKCS#7 message with its 4-way certificate chain:

```
======= X.509 certificate listing ==========
Serial Number: 04:05:06:07:08:09:00:01
Signature Algorithm: ML-DSA44 <builtin hash>
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
====== End one certificate ==========
Serial Number: 03:03:04:05:06:07:08:09
Signature Algorithm: ML-DSA65 <builtin hash>
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
====== End one certificate ==========
Serial Number: 02:03:03:04:05:06:07:08
Signature Algorithm: ML-DSA87 <builtin hash>
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
====== End one certificate ==========
Serial Number: 01:02:03:04:05:06:07:08
Signature Algorithm: ML-DSA87 <builtin hash>
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
====== End one certificate ==========
======= PKCS7 signed info listing ==========
Serial Number: 04:05:06:07:08:09:00:01
Signature Algorithm: ML-DSA44 <builtin hash>
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
Signed Authinfo = 8189304f06092a864886f70d0109043142044016cc53131266f12f8dbb5b10de31c1868a44c1b1a4eadb0d1ea43e36802cf5fe7aa2c22659be36ea3f8d4462a66eb2500533b1ac8378f8f96ae6e91031779878301806092a864886f70d010903310b00092a864886f70d010701301c06092a864886f70d010905310f170d3234313132313038313833385a
Signature Algorithm: ML-DSA87 <builtin hash>
AuthID[0] = 0d0e0f00010203
AuthID[1] = 
AuthID[2] = 
signerInfos messageDigest = 7f155a4b8be3f85994060b90c3ec0e6a2e4dc5dac44d904940289bf3006b421b8b7613825368d6c451676acd5b03df307f8921171fff4261fd0584ac0653160a
Message digest algorithm: SHA3-512
Size of protected data: 7606
====== End one PKCS7 signed info listing ==========
```

## PKCS#7 Trust Verification

The trust verification is implemented with the API call of `lc_pkcs7_verify`.
It applies the following approach:

* The signer of the message must be present in the PKCS#7 message and its
  signature of the message is verified along with the signer certificate
  validity.

* If no trust store is used, ensure that the certificate chain contains a root
  CA and that there is a certificate chain starting with the message signer
  to the CA. If such certificate chain validation was successful, the
  PKCS#7 message verification succeeds.
  
* When generating a trust store, all added certificates are validated to lead
  to a root CA found in the trust store. This implies that the order of adding
  certificates to the trust store matters: first the root CA must be added
  followed by certificates signed by the root CA followed by further
  subordinated certificates.
  
* If a trust store is used, ensure that the certificate chain starts with the
  signer of the message and leads to a certificate found in the trust store.
  As any certificate in the trust store is guaranteed to have a valid chain to
  a root CA (see preceding bullet), no further certificate chain validation is
  applied. If such certificate chain validation is successful, the
  PKCS#7 message verification succeeds.
  
* A root CA or intermediate CA certificate are required to possess the key
  usage flag of keyCertSign for successful validation.
  
* A caller can provide the required key usage or EKU flags that a signer must
  bear for successful validation to `lc_pkcs7_verify` or via
  `lc_pkcs7_generator`.
