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
