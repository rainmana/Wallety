import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RlpTest {
    private static final Map<String, String> TABLE = Abi.table("");
    private static final byte[] TO = Abi.fromHex("0x3535353535353535353535353535353535353535");

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
        byte[] payload = list(
                uint(1), uint(42), uint(1_000_000_000L), uint(30_000_000_000L), uint(60_000),
                bytes(TO), uint(0), bytes(calldata),
                list(list(bytes(TO), list(bytes(new byte[32]), bytes(new byte[32])))),
                uint(1), bytes(new byte[]{0x11}), bytes(new byte[]{0x22}));
        byte[] raw = concat(new byte[]{0x02}, payload);

        Rlp.Described tx = Rlp.describeTransaction(raw, TABLE);
        assertEquals("transfer → 0x3535…3535", tx.label);
        assertEquals(List.of(
                "raw:      " + raw.length + " bytes, EIP-1559 (type 2)",
                "chainId:  1",
                "nonce:    42",
                "maxPriorityFeePerGas: 1000000000  (1 gwei)",
                "maxFeePerGas: 30000000000  (30 gwei)",
                "gasLimit: 60000",
                "to:       0x3535353535353535353535353535353535353535",
                "value:    0  (0 wei = 0 ether)",
                "accessList: 1 entries",
                "  0x3535353535353535353535353535353535353535  2 storage keys",
                "yParity:  1",
                "r:        0x11",
                "s:        0x22",
                "selector 0xa9059cbb  transfer(address,uint256)",
                "  [0] address  0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
                "  [1] uint256  1"), tx.lines);
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

        byte[] setCode = concat(new byte[]{0x04}, list(
                uint(1), uint(7), uint(1), uint(1), uint(1), bytes(TO), uint(0), bytes(new byte[0]), list(),
                list(list(uint(1), bytes(TO), uint(3), uint(0), uint(1), uint(1))),
                uint(0), uint(1), uint(1)));
        Rlp.Described auth = Rlp.describeTransaction(setCode, TABLE);
        assertEquals("(value transfer) → 0x3535…3535", auth.label);
        assertTrue(auth.lines.contains("authorizationList: 1 entries"));
        assertTrue(auth.lines.contains("  chainId=1 address=0x3535353535353535353535353535353535353535 nonce=3"));
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
