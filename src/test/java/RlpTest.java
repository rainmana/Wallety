import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RlpTest {
    private static final Map<String, String> TABLE = Abi.table("");
    private static final byte[] TO = Abi.fromHex("0x3535353535353535353535353535353535353535");
    // EIP-155 example key; its address is the vector's sender.
    private static final BigInteger KEY = new BigInteger("4646464646464646464646464646464646464646464646464646464646464646", 16);
    private static final String SENDER = "0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f";

    @Test
    void decodesTheEip155SpecificationVector() {
        // From EIP-155: nonce 9, gasPrice 20 gwei, gas 21000, to 0x3535..., value 1 ether, chainId 1.
        byte[] raw = Abi.fromHex("0xf86c098504a817c800825208943535353535353535353535353535353535353535"
                + "880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276"
                + "a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83");
        Rlp.Described tx = Rlp.describeTransaction(raw, TABLE);
        assertEquals("(value transfer) → 0x3535…3535", tx.label);
        assertEquals(List.of(
                "raw:      110 bytes, legacy",
                "from:     " + SENDER + "  (recovered from signature)",
                "nonce:    9",
                "gasPrice: 20000000000  (20 gwei)",
                "gasLimit: 21000",
                "to:       0x3535353535353535353535353535353535353535",
                "value:    1000000000000000000  (1000000000000000000 wei = 1 ether)",
                "v:        37  (EIP-155 chainId 1)",
                "r:        0x28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276",
                "s:        0x67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83",
                "data: empty (plain value transfer or fallback)"), tx.lines);
    }

    @Test
    void decodesAnEip1559TransactionWithCalldataAndAccessList() {
        byte[] calldata = Abi.fromHex("0xa9059cbb000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045"
                + "0000000000000000000000000000000000000000000000000000000000000001");
        byte[] unsigned = list(
                uint(1), uint(42), uint(1_000_000_000L), uint(30_000_000_000L), uint(60_000),
                bytes(TO), uint(0), bytes(calldata),
                list(list(bytes(TO), list(bytes(new byte[32]), bytes(new byte[32])))));
        byte[] raw = signed(0x02, unsigned, KEY);

        Rlp.Described tx = Rlp.describeTransaction(raw, TABLE);
        assertEquals("transfer → 0x3535…3535", tx.label);
        List<String> lines = new ArrayList<>(tx.lines);
        assertTrue(lines.remove(11).matches("yParity:  [01]"));
        assertTrue(lines.remove(11).startsWith("r:        0x"));
        assertTrue(lines.remove(11).startsWith("s:        0x"));
        assertEquals(List.of(
                "raw:      " + raw.length + " bytes, EIP-1559 (type 2)",
                "from:     " + SENDER + "  (recovered from signature)",
                "chainId:  1",
                "nonce:    42",
                "maxPriorityFeePerGas: 1000000000  (1 gwei)",
                "maxFeePerGas: 30000000000  (30 gwei)",
                "gasLimit: 60000",
                "to:       0x3535353535353535353535353535353535353535",
                "value:    0  (0 wei = 0 ether)",
                "accessList: 1 entries",
                "  0x3535353535353535353535353535353535353535  2 storage keys",
                "selector 0xa9059cbb  transfer(address,uint256)",
                "  [0] address  0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
                "  [1] uint256  1"), lines);
    }

    @Test
    void decodesContractCreationAndSetCodeAuthorizations() {
        byte[] creation = concat(new byte[]{0x02}, list(
                uint(1), uint(0), uint(1), uint(1), uint(1), bytes(new byte[0]), uint(0),
                bytes(new byte[]{0x60, (byte) 0x80}), list(), uint(0), uint(1), uint(1)));
        Rlp.Described tx = Rlp.describeTransaction(creation, TABLE);
        assertEquals("(contract creation)", tx.label);
        assertTrue(tx.lines.contains("to:       (contract creation)"));
        assertTrue(tx.lines.contains("initcode: 2 bytes"));

        byte[] authorization = signed(0x05, list(uint(1), bytes(TO), uint(3)), KEY);
        byte[] setCode = concat(new byte[]{0x04}, list(
                uint(1), uint(7), uint(1), uint(1), uint(1), bytes(TO), uint(0), bytes(new byte[0]), list(),
                list(java.util.Arrays.copyOfRange(authorization, 1, authorization.length)),
                uint(0), uint(1), uint(1)));
        Rlp.Described auth = Rlp.describeTransaction(setCode, TABLE);
        assertEquals("(value transfer) → 0x3535…3535", auth.label);
        // r = s = 1 with yParity 0 is a valid signature for some key, so a sender is still recovered.
        assertTrue(auth.lines.get(1).startsWith("from:     0x"), auth.lines.get(1));
        assertTrue(auth.lines.contains("authorizationList: 1 entries"));
        assertTrue(auth.lines.contains("  chainId=1 address=0x3535353535353535353535353535353535353535 nonce=3 authority=" + SENDER));
    }

    @Test
    void malformedInputIsReportedNotThrown() {
        assertEquals("unknown type", Rlp.describeTransaction(new byte[]{0x7f, 0x00}, TABLE).label);
        Rlp.Described truncated = Rlp.describeTransaction(Abi.fromHex("0x02f86b01"), TABLE);
        assertEquals("EIP-1559 (type 2) (undecodable)", truncated.label);
        assertEquals("raw:      4 bytes, EIP-1559 (type 2)", truncated.lines.get(0));
        assertTrue(truncated.lines.get(1).startsWith("(does not decode as EIP-1559 (type 2): "));

        Rlp.Described notList = Rlp.describeTransaction(new byte[]{0x02, (byte) 0x83, 1, 2, 3}, TABLE);
        assertTrue(notList.lines.get(1).contains("not an RLP list"));

        Rlp.Described shortList = Rlp.describeTransaction(concat(new byte[]{0x02}, list(uint(1), uint(2))), TABLE);
        assertTrue(shortList.lines.contains("(expected 12 fields, found 2)"));
        assertEquals("(no data field)", shortList.label);

        assertThrows(IllegalArgumentException.class, () -> Rlp.decode(new byte[]{(byte) 0xc1}));
        assertThrows(IllegalArgumentException.class, () -> Rlp.decode(new byte[]{(byte) 0xb8, 0x01, 0x00}));
        assertThrows(IllegalArgumentException.class, () -> Rlp.decode(new byte[]{0x01, 0x02}));
        assertEquals(BigInteger.ZERO, Rlp.decode(new byte[]{(byte) 0x80}).uint());
        assertEquals(List.of(), Rlp.decode(new byte[]{(byte) 0xc0}).list);
    }

    @Test
    void secp256k1RecoversAndRejects() {
        assertEquals(SENDER, Secp256k1.address(concat(
                Secp256k1.pad32(Secp256k1.mul(Secp256k1.G, KEY)[0]), Secp256k1.pad32(Secp256k1.mul(Secp256k1.G, KEY)[1]))));
        byte[] hash = Keccak.hash256("hello");
        BigInteger[] sig = sign(hash, KEY);
        assertEquals(SENDER, Secp256k1.address(Secp256k1.recover(hash, sig[0], sig[1], sig[2].intValue())));
        assertNotEquals(SENDER, Secp256k1.address(Secp256k1.recover(hash, sig[0], sig[1], 1 - sig[2].intValue())));
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.recover(hash, sig[0], sig[1], 2));
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.recover(hash, Secp256k1.N, sig[1], 0));
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.recover(hash, sig[0], BigInteger.ZERO, 0));
        assertThrows(IllegalArgumentException.class, () -> Secp256k1.recover(new byte[31], sig[0], sig[1], 0));
        // Round trip of the encoder against the decoder.
        byte[] raw = Abi.fromHex("0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080");
        assertThrows(IllegalArgumentException.class, () -> Rlp.decode(raw));  // truncated list header
        byte[] whole = list(uint(9), uint(20_000_000_000L), uint(21000), bytes(TO), uint(1_000_000_000_000_000_000L), bytes(new byte[0]));
        assertArrayEquals(whole, Rlp.encode(Rlp.decode(whole)));
        assertArrayEquals(bytes(new byte[60]), Rlp.encode(Rlp.decode(bytes(new byte[60]))));
    }

    // --- test-side signer and minimal RLP encoder ---------------------------

    /** Typed payload (0x02 tx, 0x05 authorization) signed over keccak(type || unsignedList). */
    private static byte[] signed(int type, byte[] unsignedList, BigInteger key) {
        BigInteger[] sig = sign(Keccak.hash256(concat(new byte[]{(byte) type}, unsignedList)), key);
        // Re-open the list and append yParity, r, s.
        Rlp.Item fields = Rlp.decode(unsignedList);
        List<Rlp.Item> all = new ArrayList<>(fields.list);
        all.add(Rlp.uint(sig[2]));
        all.add(Rlp.uint(sig[0]));
        all.add(Rlp.uint(sig[1]));
        return concat(new byte[]{(byte) type}, Rlp.encode(new Rlp.Item(null, all)));
    }

    /** Deterministic low-s ECDSA; returns {r, s, recId}. Test-only: fixed nonce. */
    private static BigInteger[] sign(byte[] hash, BigInteger key) {
        BigInteger k = new BigInteger(1, Keccak.hash256(hash)).mod(Secp256k1.N);
        BigInteger[] point = Secp256k1.mul(Secp256k1.G, k);
        BigInteger r = point[0].mod(Secp256k1.N);
        BigInteger z = new BigInteger(1, hash);
        BigInteger s = k.modInverse(Secp256k1.N).multiply(z.add(r.multiply(key))).mod(Secp256k1.N);
        int recId = point[1].testBit(0) ? 1 : 0;
        if (s.compareTo(Secp256k1.N.shiftRight(1)) > 0) {
            s = Secp256k1.N.subtract(s);
            recId ^= 1;
        }
        return new BigInteger[]{r, s, BigInteger.valueOf(recId)};
    }

    // --- minimal RLP encoder for test fixtures ------------------------------

    private static byte[] uint(long value) {
        byte[] magnitude = BigInteger.valueOf(value).toByteArray();
        int skip = 0;
        while (skip < magnitude.length - 1 && magnitude[skip] == 0) {
            skip++;
        }
        byte[] trimmed = value == 0 ? new byte[0] : java.util.Arrays.copyOfRange(magnitude, skip, magnitude.length);
        return bytes(trimmed);
    }

    private static byte[] bytes(byte[] data) {
        if (data.length == 1 && (data[0] & 0xff) < 0x80) {
            return data;
        }
        return concat(lengthPrefix(0x80, data.length), data);
    }

    private static byte[] list(byte[]... items) {
        byte[] payload = concat(items);
        return concat(lengthPrefix(0xc0, payload.length), payload);
    }

    private static byte[] lengthPrefix(int base, int length) {
        if (length <= 55) {
            return new byte[]{(byte) (base + length)};
        }
        byte[] lengthBytes = BigInteger.valueOf(length).toByteArray();
        if (lengthBytes[0] == 0) {
            lengthBytes = java.util.Arrays.copyOfRange(lengthBytes, 1, lengthBytes.length);
        }
        return concat(new byte[]{(byte) (base + 55 + lengthBytes.length)}, lengthBytes);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }
}
