Description
---
A specification written in [Hacspec](https://github.com/hacspec/hacspec) for Shamir's secret sharing scheme over secp256k1's curve order.
I  made the following decisions to simplify the implementation:
- no tagged hashes in nonce generation
- didn't assert the user inputs
  - hacspec prevents this
- user can't provide any auxiliary randomness


API Details
---
- `generate_shares`
   - generates `n` shamir shares for the given shared secret
   - `t` of these shares are sufficent to reconstruct the shared secret
```rust
pub fn generate_shares(secret: SharedSecret, t: usize, n:usize) -> Seq<ShamirShare>
```
- `recover_secret`
   - reconstructs the secret from the given shares (atleast `t` needed)
```rust
pub fn recover_secret(shares: &Seq<ShamirShare>) -> SharedSecret
```

Build Instructions
---
To build & test:
```
cargo build
cargo test
```
To typecheck hacspec specification:
  - install the typechecker (follow these [instructions](https://github.com/hacspec/hacspec#typechecking))
  - there will be two different version of `hacspec_lib` compiled when you run `cargo build`
    - this is a known issue within the hacspec community (see [this issue](https://github.com/hacspec/hacspec/issues/141))
    - so, you need to manually delete one of the two versions (`.remeta` and `.rlib` files) before running the typechecker
    - you can find the binaries in `target/debug/dep/` directory (named `libhacspec_lib-****.rmeta`)
```
cargo hacspec hacspec-sss
```