import burp.api.montoya.core.HighlightColor;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DecoderTest {
    private static final Map<String, String> TABLE = Abi.table("");
    private static final String ADDR = "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045";

    @Test
    void keccakMatchesKnownVectors() {
        assertEquals("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                Keccak.hex(Keccak.hash256(""), 32));
        assertEquals("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
                Keccak.hex(Keccak.hash256("abc"), 32));
        // Longer than one 136-byte block.
        assertEquals("c2a4b8d3f9a1d9f3b5c4c3c4b5c0a8d5e6d3c3a0b2b8c4c5d5e3a0b1c2d3e4f5".length(),
                Keccak.hex(Keccak.hash256("a".repeat(300)), 32).length());
        assertEquals("a9059cbb", Keccak.selector("transfer(address,uint256)"));
        assertEquals("095ea7b3", Keccak.selector("approve(address,uint256)"));
        assertEquals("23b872dd", Keccak.selector("transferFrom(address,address,uint256)"));
        assertEquals("ac9650d8", Keccak.selector("multicall(bytes[])"));
        assertEquals("252dba42", Keccak.selector("aggregate((address,bytes)[])"));
    }

    @Test
    void bundledTableResolvesCommonSelectorsAndExtrasAreAdded() {
        assertEquals("transfer(address,uint256)", TABLE.get("a9059cbb"));
        assertEquals("setApprovalForAll(address,bool)", TABLE.get("a22cb465"));
        Map<String, String> extra = Abi.table("  frob(uint256,bool)\nnonsense  ; foo(bytes32)");
        assertEquals("frob(uint256,bool)", extra.get(Keccak.selector("frob(uint256,bool)")));
        assertEquals("foo(bytes32)", extra.get(Keccak.selector("foo(bytes32)")));
        assertEquals(TABLE.size() + 2, extra.size());
    }

    @Test
    void decodesStaticArguments() {
        String data = "0xa9059cbb" + ADDR + "0000000000000000000000000000000000000000000000000de0b6b3a7640000";
        List<String> lines = Abi.describeCalldata(data, TABLE);
        assertEquals(List.of(
                "selector 0xa9059cbb  transfer(address,uint256)",
                "  [0] address  0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
                "  [1] uint256  1000000000000000000"), lines);
    }

    @Test
    void decodesDynamicBytesArrayAndTuples() {
        // multicall(bytes[]) with two calls: 0x11223344 and 0xaabb
        String data = "0xac9650d8"
                + word(0x20)   // offset of bytes[]
                + word(2)      // length
                + word(0x40)   // offset of [0] relative to array data start
                + word(0x80)   // offset of [1]
                + word(4) + "1122334400000000000000000000000000000000000000000000000000000000"
                + word(2) + "aabb000000000000000000000000000000000000000000000000000000000000";
        List<String> lines = Abi.describeCalldata(data, TABLE);
        assertEquals(List.of(
                "selector 0xac9650d8  multicall(bytes[])",
                "  [0] bytes[]  [2 items]",
                "    [0] bytes  0x11223344  (4 bytes)",
                "    [1] bytes  0xaabb  (2 bytes)"), lines);

        // aggregate((address,bytes)[]) with one call
        String agg = "0x252dba42"
                + word(0x20)   // offset of array
                + word(1)      // length
                + word(0x20)   // offset of tuple[0] relative to array data start
                + ADDR + word(0x40)   // tuple head: address, offset of bytes
                + word(3) + "abcdef0000000000000000000000000000000000000000000000000000000000";
        assertEquals(List.of(
                "selector 0x252dba42  aggregate((address,bytes)[])",
                "  [0] tuple[]  [1 items]",
                "    [0] tuple",
                "      [0] address  0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
                "      [1] bytes  0xabcdef  (3 bytes)"), Abi.describeCalldata(agg, TABLE));
    }

    @Test
    void decodesStringsAndSignedIntegers() {
        Map<String, String> table = Abi.table("say(string,int8)");
        String data = "0x" + Keccak.selector("say(string,int8)")
                + word(0x40)
                + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"  // -1
                + word(5) + "68692022790000000000000000000000000000000000000000000000000000";  // hi "y
        assertEquals(List.of(
                "selector 0x" + Keccak.selector("say(string,int8)") + "  say(string,int8)",
                "  [0] string  \"hi \\\"y\"",
                "  [1] int8  -1"), Abi.describeCalldata(data, table));
    }

    @Test
    void malformedCalldataFallsBackToRawWordsWithoutThrowing() {
        String truncated = "0xa9059cbb" + ADDR.substring(0, 40);
        List<String> lines = Abi.describeCalldata(truncated, TABLE);
        assertEquals("selector 0xa9059cbb  transfer(address,uint256)", lines.get(0));
        assertEquals("  (arguments do not decode as transfer(address,uint256))", lines.get(1));
        assertTrue(lines.get(2).startsWith("  word[0] 0x"));

        String hugeOffset = "0xac9650d8" + "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assertEquals("  (arguments do not decode as multicall(bytes[]))", Abi.describeCalldata(hugeOffset, TABLE).get(1));

        assertEquals(List.of("selector 0xdeadbeef  (unknown; add the signature under Settings > Wallety)",
                "  word[0] 0x01"), Abi.describeCalldata("0xdeadbeef01", TABLE));
        assertEquals(List.of("data: not valid hex"), Abi.describeCalldata("0xzz", TABLE));
        assertEquals(List.of("data: empty (plain value transfer or fallback)"), Abi.describeCalldata("0x", TABLE));
    }

    @Test
    void summarizesCallsBatchesAndRawTransactions() {
        String call = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"eth_call\",\"params\":[{\"to\":\"0x1234567890abcdef1234567890abcdef12345678\","
                + "\"value\":\"0xde0b6b3a7640000\",\"data\":\"0xa9059cbb" + ADDR + word(1) + "\"},\"latest\"]}";
        Web3Summary single = Web3Summary.describe(call, TABLE);
        assertEquals("eth_call transfer → 0x1234…5678", single.note);
        assertEquals(HighlightColor.NONE, single.highlight);
        assertEquals("eth_call  (id 7)\n"
                + "  to:     0x1234567890abcdef1234567890abcdef12345678\n"
                + "  value:  0xde0b6b3a7640000  (1000000000000000000 wei = 1 ether)\n"
                + "  block:  \"latest\"\n"
                + "  selector 0xa9059cbb  transfer(address,uint256)\n"
                + "    [0] address  0xd8da6bf26964af9d7eed9e03e53415d37aa96045\n"
                + "    [1] uint256  1\n", single.detail);

        String batch = "[" + call + ",{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x02f86b01\"]},"
                + "{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[]},{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"eth_blockNumber\"}]";
        Web3Summary multi = Web3Summary.describe(batch, TABLE);
        assertEquals("batch[4]: eth_call eth_sendRawTransaction eth_blockNumberx2", multi.note);
        assertEquals(HighlightColor.ORANGE, multi.highlight);
        assertTrue(multi.detail.contains("[1] eth_sendRawTransaction  (id 8)\n  raw:      4 bytes, EIP-1559 (type 2)\n  (does not decode as"));
        assertTrue(multi.detail.contains("[2] eth_blockNumber  (notification)\n  params: []\n"));
        assertTrue(multi.detail.contains("[3] eth_blockNumber  (id 9)\n  params: none\n"));

        assertNull(Web3Summary.describe(null, TABLE));
        assertNull(Web3Summary.describe("{\"jsonrpc\":\"1.0\",\"method\":\"eth_call\"}", TABLE));
        assertNull(Web3Summary.describe("{\"jsonrpc\":\"2.0\",", TABLE));
        assertNull(Web3Summary.describe("[]", TABLE));
    }

    private static String word(int value) {
        return String.format("%064x", value);
    }
}
