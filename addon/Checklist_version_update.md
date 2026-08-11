# Checklist for Updating Leancrypto Version

## Version Number Update

The version number is to be updated in the following files:

- meson.build: project.version

- leancrypto.spec

- linux_kernel/Kbuild.version

- dkms.conf

## ABI Changes (including API Changes)

- bump (at least) minor version

- update version.lds, consider:

```
In an ELF linker version script, you don't mark a symbol as having changed ABI
directly. Instead, you assign the changed ABI to a new symbol version.

LIBFOO_1.0 {
    global:
        foo;
};

LIBFOO_2.0 {
    global:
        foo;
} LIBFOO_1.0;

This says that foo has a new ABI in LIBFOO_2.0, while the old LIBFOO_1.0 ABI
remains available.

If you need to keep both ABIs simultaneously, use symbol versioning:

int foo_v1(int x);
int foo_v2(int x);

__asm__(".symver foo_v1,foo@LIBFOO_1.0");

Here:

foo@LIBFOO_1.0 = old ABI

foo@@LIBFOO_2.0 = new/default ABI

Existing binaries linked against LIBFOO_1.0 continue to call the old
implementation. New binaries get LIBFOO_2.0.

If you don't need backward compatibility, you can simply change the function and
bump the library's ABI version/SONAME as appropriate. A linker version script
isn't itself an ABI compatibility mechanism; symbol versions are useful when
you want multiple ABI revisions of the same symbol to coexist.

If you tell me whether you're using GNU ld, gold, or lld, I can show the
recommended version-script syntax for an ABI-breaking change, including how to 
detect accidental ABI changes in CI.
```
