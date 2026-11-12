import java.math.BigInteger;
import java.util.Arrays;

/**
 * Just enough secp256k1 to recover a public key from an ECDSA signature.
 * Verification only: no private keys are handled, so constant time is not a goal.
 */
// ponytail: affine BigInteger arithmetic, ~5 ms per recovery; swap for Bouncy Castle if it ever matters.
final class Secp256k1 {
    static final BigInteger P = new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    static final BigInteger N = new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    static final BigInteger[] G = {
            new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
            new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)};
    private static final BigInteger SEVEN = BigInteger.valueOf(7);

    private Secp256k1() {
    }

    /** Uncompressed public key (x || y, 64 bytes) that signed hash with (r, s), recId 0 or 1. Throws if invalid. */
    static byte[] recover(byte[] hash, BigInteger r, BigInteger s, int recId) {
        if (hash.length != 32 || recId < 0 || recId > 1 || !inRange(r) || !inRange(s)) {
            throw new IllegalArgumentException("invalid signature");
        }
        // ponytail: recId 2/3 (r + N as x) never occurs in practice; not handled.
        BigInteger x = r;
        BigInteger ySquared = x.modPow(BigInteger.valueOf(3), P).add(SEVEN).mod(P);
        BigInteger y = ySquared.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (!y.modPow(BigInteger.TWO, P).equals(ySquared)) {
            throw new IllegalArgumentException("r is not an x coordinate on the curve");
        }
        if (y.testBit(0) != (recId == 1)) {
            y = P.subtract(y);
        }
        BigInteger z = new BigInteger(1, hash);
        BigInteger rInv = r.modInverse(N);
        // Q = r^-1 * (s*R - z*G)
        BigInteger[] q = add(mul(new BigInteger[]{x, y}, s.multiply(rInv).mod(N)),
                mul(G, z.negate().multiply(rInv).mod(N)));
        if (q == null) {
            throw new IllegalArgumentException("recovered point at infinity");
        }
        byte[] out = new byte[64];
        System.arraycopy(pad32(q[0]), 0, out, 0, 32);
        System.arraycopy(pad32(q[1]), 0, out, 32, 32);
        return out;
    }

    /** Ethereum address of an uncompressed public key: last 20 bytes of keccak(x || y). */
    static String address(byte[] publicKey) {
        byte[] hash = Keccak.hash256(publicKey);
        return "0x" + Keccak.hex(Arrays.copyOfRange(hash, 12, 32), 20);
    }

    static boolean inRange(BigInteger v) {
        return v.signum() > 0 && v.compareTo(N) < 0;
    }

    /** Scalar multiplication by double-and-add; null is the point at infinity. */
    static BigInteger[] mul(BigInteger[] point, BigInteger k) {
        BigInteger[] result = null;
        BigInteger[] addend = point;
        for (int i = 0; i < k.bitLength(); i++) {
            if (k.testBit(i)) {
                result = add(result, addend);
            }
            addend = add(addend, addend);
        }
        return result;
    }

    static BigInteger[] add(BigInteger[] a, BigInteger[] b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        BigInteger lambda;
        if (a[0].equals(b[0])) {
            if (!a[1].equals(b[1]) || a[1].signum() == 0) {
                return null;
            }
            lambda = a[0].pow(2).multiply(BigInteger.valueOf(3)).multiply(a[1].shiftLeft(1).modInverse(P)).mod(P);
        } else {
            lambda = b[1].subtract(a[1]).multiply(b[0].subtract(a[0]).modInverse(P)).mod(P);
        }
        BigInteger x = lambda.pow(2).subtract(a[0]).subtract(b[0]).mod(P);
        BigInteger y = lambda.multiply(a[0].subtract(x)).subtract(a[1]).mod(P);
        return new BigInteger[]{x, y};
    }

    static byte[] pad32(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[32];
        int n = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - n, out, 32 - n, n);
        return out;
    }
}
