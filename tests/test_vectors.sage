import secrets
import hashlib

# Arbitrary upper bound
MAX_SHARES = 32

# Order of secp256k1 elliptic curve
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
R.<x> = PolynomialRing(FiniteField(p))

def nonce32(D, k, n, i):
    sha256 = hashlib.sha256()

    sha256.update(D.to_bytes(32, "big"))
    sha256.update(k.to_bytes(4, "big"))
    sha256.update(n.to_bytes(4, "big"))
    sha256.update(i.to_bytes(4, "big"))

    sha256_hex = sha256.hexdigest()
    nonce = int(sha256_hex, 16) % p

    return ZZ(nonce)

def sss_get_shares(D, k, n):
    """
    Splits the secret value D into n shares; k of n are needed
    to reconstruct the secret.

    D - 256-bit integer in [0, p)
    """
    assert 0 <= D < p
    assert 1 < k <= n <= MAX_SHARES

    # construct secret polynomial (degree = k-1)
    q = D
    for i in range(1, k):
        a_i = nonce32(int(D), int(k), int(n), int(i))
        assert 0 < a_i < p
        q += a_i * x^i

    return [(i, q(i)) for i in range(1, n + 1)]

def _eval_lagrange_interpolate(t, xs, ys):
    """
    Evaluates the iterpolated polynomial (uses lagrange basis
    function) at point x.
    t  - 256-bit integer in [0, p)
    xs - list - x co-ordinate of the shares
    ys - list - y co-ordinate of the shares
    """
    # Algorithm
    # 1. calc sum(y_i * delta_{j,x_i}) mod p, i = 0,1..k-1
    # 2. delta_{j,x_i} = {(x -x0).(x -x1)...(x -x_k-1)/
    #                     (xi-x0).(xi-x1)...(xi-x_k-1)} mod p
    poly = R(0)
    for i in range(len(ys)):
        delta = R(1)
        x_i = xs[i]
        y_i = ys[i]
        for x_j in xs:
            if(x_j == x_i):
                continue
            delta = delta*((x - x_j)/(x_i - x_j))
        poly += y_i*delta

    return poly(t)


def sss_recover_secret(shares):
    """
    Recovers the secret D from the given shares.

    shares - list of points (x_i, y_i) on the polynomial
    """
    # Algorithm
    # 1. assert for distinct x_i
    # 2. evaluate the polynomial at 0
    xs = [share[0] for share in shares]
    ys = [share[1] for share in shares]
    assert len(xs) == len(set(xs))

    return _eval_lagrange_interpolate(0, xs, ys)

def print_shares(shares):
    for i, fi in shares:
        print("({}, {})".format(hex(int(i)).upper(), hex(int(fi)).upper()))

def print_secret(secret):
    print("secret: {}".format(hex(int(secret)).upper()))

def generate_test_vectors():
    seckey = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF

    print("test_vector1:")
    shares1 = sss_get_shares(seckey, 2, 3)
    print_shares(shares1)
    print_secret(sss_recover_secret(shares1))

    print("test_vector2:")
    shares2 = sss_get_shares(seckey, 3, 5)
    print_shares(shares2)
    print_secret(sss_recover_secret(shares1))

    print("test_vector3:")
    shares3 = sss_get_shares(seckey, 4, 7)
    print_shares(shares3)
    print_secret(sss_recover_secret(shares1))

if __name__ == '__main__':
    generate_test_vectors()