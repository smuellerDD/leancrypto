# Cross compilation

Perform cross compilation of leancrypto with the following command:

`meson setup --cross-file cross-compile/<CROSS-BUILD-FILE> build`

followed by

`meson compile -C build`
