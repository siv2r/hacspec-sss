use hacspec_lib::*;
use hacspec_sss::*;

#[test]
fn test_vector1() {
    let seckey = SharedSecret::from_hex("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
    let t: usize = 2;
    let n: usize = 3;
    let mut expected_shares = Seq::<ShamirShare>::new(n);
    expected_shares[0] = (
        FieldElement::from_literal(1u128),
        FieldElement::from_hex("4CCB1AE9AE869E3A31185A94A8FF9A8D1686143C17256AF06B5AADCC222180A0"),
    );
    expected_shares[1] = (
        FieldElement::from_literal(2u128),
        FieldElement::from_hex("E1B4E470D2201209A2BF5CA8B50A415184D3EF4FA4DE9BC5EF02E120C2E87292"),
    );
    expected_shares[2] = (
        FieldElement::from_literal(3u128),
        FieldElement::from_hex("769EADF7F5B985D914665EBCC114E8173872ED7C834F2C5FB2D8B5E893792343"),
    );

    // test generate_shares API
    let gen_shares = generate_shares(seckey, t, n);
    for i in 1..n {
        assert_eq!(gen_shares[i-1], expected_shares[i-1]);
    }

    // test recover_secret API
    let mut shares = Seq::<ShamirShare>::new(t);
    for i in 1..(t+1) {
        shares[i-1] = expected_shares[i-1];
    }

    let recovered_secret = recover_secret(&shares);
    assert_eq!(recovered_secret.to_hex(), seckey.to_hex());
}
