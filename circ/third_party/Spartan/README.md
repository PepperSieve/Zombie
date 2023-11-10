## Fork of Spartan for ZKMB
to generate header for libsnark
```
cargo install --force cbindgen
cbindgen --config cbindgen.toml --crate spartan --output spartan_libsnark.h
```