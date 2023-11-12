use hacspec_lib::*;
use hacspec_sha256::*;


// order of secp256k1 elliptic curve
public_nat_mod!(
    type_name: FieldElement,
    type_of_canvas: FieldElementCanvas,
    bit_size_of_field: 256,
    modulo_value: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

//todo: use named struct instead?
pub type ShamirShare = (FieldElement, FieldElement);

bytes!(Bytes32, 32);
pub type SharedSecret = Bytes32;

// avoids tagged hash for simplicity
fn nonce32(
    secret: SharedSecret,
    t: usize,
    n: usize,
    i: usize,
) -> Bytes32 {
    // convert t, n, and i into bytes of secret value
    let t = U32::classify(t as u32);
    let n = U32::classify(n as u32);
    let i = U32::classify(i as u32);
    let hash_inp = ByteSeq::from_seq(&secret)
        .concat(&U32_to_be_bytes(t))
        .concat(&U32_to_be_bytes(n))
        .concat(&U32_to_be_bytes(i));
    let hash = sha256(&hash_inp);
    Bytes32::from_seq(&hash)
}

//todo: use hacspec internal `poly!` type instead?
// computes poly(x)
fn eval_poly(
    poly: &Seq<FieldElement>,
    x: FieldElement,
) -> FieldElement {
    let mut res = poly[0];
    let len = poly.len();

    for i in 1..len {
        res = res + poly[i]*(x.pow(i as u128));
    }

    res
}

pub fn generate_shares(
    secret: SharedSecret,
    t: usize,
    n: usize,
) -> Seq<ShamirShare> {
    //todo: hacspec prevents using `assert!`
    //     - use `u32Word` for t, and n instead?
    // assert!(t <= u32::MAX as usize);
    // assert!(n <= u32::MAX as usize);

    let mut out = Seq::<ShamirShare>::new(n);
    let mut poly = Seq::<FieldElement>::new(t);

    poly[0] = FieldElement::from_byte_seq_be(&secret);

    // generate coefficients for the `poly`
    for i in 1..t {
        let entropy = nonce32(secret, t, n, i);
        let coeff = FieldElement::from_byte_seq_be(&entropy);
        poly[i] = coeff;
    }

    for i in 1..(n+1) {
        let x_i = FieldElement::from_literal(i as u128);
        let y_i = eval_poly(&poly, x_i);
        let s_i: ShamirShare = (x_i, y_i);

        out[i-1] = s_i;
    }

    out
}

pub fn recover_secret(shares: &Seq<ShamirShare>) -> SharedSecret {
    let mut res = FieldElement::ZERO();
    // length of co-signers set (t <= alpha <= n)
    let alpha = shares.len();

    // eval lagrange interpolated poly (at x = 0)
    for i in 1..(alpha+1) {
        let (x_i, y_i) = shares[i-1];
        let mut lam_i = FieldElement::ONE();

        // eval lagrange basis poly of y_i (at x = 0)
        for j in 1..(alpha+1) {
            if j != i {
                let (x_j, _) = shares[j-1];
                lam_i = lam_i*(x_j/(x_j - x_i));
            };
        }

        res = res + lam_i*y_i;
    }

    SharedSecret::from_seq(&res.to_byte_seq_be())
}