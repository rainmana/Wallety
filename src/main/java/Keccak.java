import java.nio.charset.StandardCharsets;

/**
 * Keccak-256 as used by Ethereum (original padding, not FIPS SHA3-256).
 * The JDK ships SHA3-256 only, which differs in the padding byte.
 */
final class Keccak {
    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};
    // Rotation offsets indexed by x + 5*y.
    private static final int[] ROT = {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14};
    private static final int RATE = 136;

    private Keccak() {
    }

    static byte[] hash256(byte[] message) {
        long[] state = new long[25];
        byte[] block = new byte[RATE];
        int offset = 0;
        while (message.length - offset >= RATE) {
            absorb(state, message, offset);
            offset += RATE;
        }
        int remaining = message.length - offset;
        System.arraycopy(message, offset, block, 0, remaining);
        block[remaining] ^= 0x01;
        block[RATE - 1] ^= (byte) 0x80;
        absorb(state, block, 0);

        byte[] out = new byte[32];
        for (int i = 0; i < 4; i++) {
            for (int b = 0; b < 8; b++) {
                out[i * 8 + b] = (byte) (state[i] >>> (8 * b));
            }
        }
        return out;
    }

    static byte[] hash256(String utf8) {
        return hash256(utf8.getBytes(StandardCharsets.UTF_8));
    }

    /** First four bytes of keccak256(signature), lowercase hex without 0x. */
    static String selector(String signature) {
        return hex(hash256(signature), 4);
    }

    static String hex(byte[] bytes, int length) {
        StringBuilder sb = new StringBuilder(length * 2);
        for (int i = 0; i < length; i++) {
            sb.append(Character.forDigit((bytes[i] >> 4) & 0xf, 16))
                    .append(Character.forDigit(bytes[i] & 0xf, 16));
        }
        return sb.toString();
    }

    private static void absorb(long[] state, byte[] data, int offset) {
        for (int i = 0; i < RATE / 8; i++) {
            long lane = 0;
            for (int b = 7; b >= 0; b--) {
                lane = (lane << 8) | (data[offset + i * 8 + b] & 0xffL);
            }
            state[i] ^= lane;
        }
        permute(state);
    }

    private static void permute(long[] a) {
        long[] c = new long[5];
        long[] b = new long[25];
        for (int round = 0; round < 24; round++) {
            for (int x = 0; x < 5; x++) {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                long d = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
                for (int y = 0; y < 25; y += 5) {
                    a[x + y] ^= d;
                }
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] = Long.rotateLeft(a[x + 5 * y], ROT[x + 5 * y]);
                }
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 25; y += 5) {
                    a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
                }
            }
            a[0] ^= RC[round];
        }
    }
}
