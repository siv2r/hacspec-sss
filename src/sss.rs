use hacspec_lib::*;

// arbitrary upper bound
const MAX_SHARES: usize = 32;

// order of secp256k1 elliptic curve
public_nat_mod!(
    type_name: FieldElement,
    type_of_canvas: FieldElementCanvas,
    bit_size_of_field: 256,
    modulo_value: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

// t & n remain const for every shares in a set
#[allow(non_camel_case_types)]
pub enum ShamirShare {
    x(FieldElement),
    y(FieldElement),
    t(usize),
    n(usize),
}

// APIs Planned:
// 1. generate_shares(secret: FieldElement, t: usize, n: usize) -> &Seq<ShamirShare>
//    1.1 we use `usize` (instead of `FieldElement`) for t and n for simplicity
// 2. recover_secret(shares: &Seq<ShamirShare>) -> FieldElement
//    2.1 eval_lagrange_poly(shares &Seq<ShamirShare>) -> FieldElement