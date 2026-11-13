import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseTest {
    private static final Map<String, String> TABLE = Abi.table("");
    private static final String ADDR = "000000000000000000000000d8da6bf26964af9d7eed9e03e53415d37aa96045";

    @Test
    void splitsSignaturesIntoArgumentsAndReturns() {
        assertEquals("getReserves()", Abi.argsPart("getReserves()(uint112,uint112,uint32)"));
        assertEquals("(uint112,uint112,uint32)", Abi.returnsPart("getReserves()(uint112,uint112,uint32)"));
        assertEquals("aggregate((address,bytes)[])", Abi.argsPart("aggregate((address,bytes)[])(uint256,bytes[])"));
        assertEquals("transfer(address,uint256)", Abi.argsPart("transfer(address,uint256)"));
        assertNull(Abi.returnsPart("transfer(address,uint256)"));
        assertEquals("08c379a0", Keccak.selector(Abi.argsPart(TABLE.get("08c379a0"))));
        assertEquals("Error(string)", TABLE.get("08c379a0"));
    }

    @Test
    void decodesReturnValues() {
        assertEquals(List.of("returns (uint256)", "  [0] uint256  1000"),
                Abi.describeReturn("0x" + word(1000), TABLE.get("70a08231")));  // balanceOf
        assertEquals(List.of("returns (uint112,uint112,uint32)",
                        "  [0] uint112  5", "  [1] uint112  7", "  [2] uint32  9"),
                Abi.describeReturn("0x" + word(5) + word(7) + word(9), "getReserves()(uint112,uint112,uint32)"));
        assertEquals(List.of("result: empty  (reverted without reason, or no contract at `to`)"),
                Abi.describeReturn("0x", "owner()(address)"));
        assertEquals(List.of("result: 32 bytes  (unknown function; add its signature under Settings > Wallety)",
                        "  word[0] 0x" + word(1)),
                Abi.describeReturn("0x" + word(1), null));
        assertEquals(List.of("result: 32 bytes  (no return types for frob(uint256); add them as name(args)(types))",
                        "  word[0] 0x" + word(1)),
                Abi.describeReturn("0x" + word(1), "frob(uint256)"));
        List<String> bad = Abi.describeReturn("0x" + word(1), "x()(bytes[])");
        assertEquals("  (result does not decode as (bytes[]))", bad.get(1));
        assertEquals(List.of("result: not valid hex"), Abi.describeReturn("0xzz", "owner()(address)"));
    }

    @Test
    void matchesResponsesToRequestsAndDecodesRevertData() {
        String requests = "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"0xabc\",\"data\":\"0x70a08231" + ADDR + "\"},\"latest\"]},"
                + "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_getBalance\",\"params\":[\"0xabc\",\"latest\"]},"
                + "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"method\":\"eth_call\",\"params\":[{\"to\":\"0xabc\",\"input\":\"0xa9059cbb" + ADDR + word(1) + "\"}]},"
                + "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x02\"]}]";
        String revert = "0x08c379a0" + word(0x20) + word(5) + "68656c6c6f" + "0".repeat(54);
        String responses = "[{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"0xde0b6b3a7640000\"},"
                + "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x" + word(42) + "\"},"
                + "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"error\":{\"code\":3,\"message\":\"execution reverted\",\"data\":\"" + revert + "\"}},"
                + "{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":\"0x" + "ab".repeat(32) + "\"},"
                + "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":null}]";
        assertEquals("[0] eth_getBalance  (id 2)\n"
                + "  result: \"0xde0b6b3a7640000\"  = 1000000000000000000  (1000000000000000000 wei = 1 ether)\n"
                + "\n"
                + "[1] eth_call  (id 1)\n"
                + "  returns (uint256)\n"
                + "    [0] uint256  42\n"
                + "\n"
                + "[2] eth_call  (id \"x\")\n"
                + "  error:  3  \"execution reverted\"\n"
                + "  selector 0x08c379a0  Error(string)\n"
                + "    [0] string  \"hello\"\n"
                + "\n"
                + "[3] eth_sendRawTransaction  (id 4)\n"
                + "  result: \"0x" + "ab".repeat(32) + "\"\n"
                + "\n"
                + "[4] ?  (id 9)\n"
                + "  result: null\n", Web3Summary.describeResponse(requests, responses, TABLE));

        String single = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x10\"}";
        assertEquals("eth_blockNumber  (id 7)\n  result: \"0x10\"  = 16\n",
                Web3Summary.describeResponse("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"eth_blockNumber\"}", single, TABLE));
        // Request unavailable or not JSON-RPC: still shows the raw result.
        assertTrue(Web3Summary.describeResponse(null, single, TABLE).startsWith("?  (id 7)\n"));
        assertNull(Web3Summary.describeResponse(requests, "{\"ok\":true}", TABLE));
        assertNull(Web3Summary.describeResponse(requests, null, TABLE));
        assertNull(Web3Summary.describeResponse(requests, "[]", TABLE));
    }

    @Test
    void summarizesResultsForTheHistoryNote() {
        String call = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"0xabc\",\"data\":\"0x70a08231" + ADDR + "\"}]}";
        assertEquals("42", Web3Summary.resultNote(call, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x" + word(42) + "\"}", TABLE));
        String reserves = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"0xabc\",\"data\":\"0x" + Keccak.selector("getReserves()") + "\"}]}";
        assertEquals("5, 7, 9", Web3Summary.resultNote(reserves,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x" + word(5) + word(7) + word(9) + "\"}", TABLE));
        String unknown = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"0xabc\",\"data\":\"0xdeadbeef\"}]}";
        assertEquals("32 bytes", Web3Summary.resultNote(unknown, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x" + word(1) + "\"}", TABLE));
        assertEquals("empty", Web3Summary.resultNote(call, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x\"}", TABLE));

        String revert = "0x08c379a0" + word(0x20) + word(5) + "68656c6c6f" + "0".repeat(54);
        assertEquals("error: execution reverted \"hello\"", Web3Summary.resultNote(call,
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":3,\"message\":\"execution reverted\",\"data\":\"" + revert + "\"}}", TABLE));
        assertEquals("error: -32000", Web3Summary.resultNote(call, "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000}}", TABLE));

        String balance = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_getBalance\",\"params\":[\"0xabc\",\"latest\"]}";
        assertEquals("1000000000000000000 (1000000000000000000 wei = 1 ether)",
                Web3Summary.resultNote(balance, "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"0xde0b6b3a7640000\"}", TABLE));
        String send = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"eth_sendRawTransaction\",\"params\":[\"0x02\"]}";
        assertEquals("0xabab…abab", Web3Summary.resultNote(send, "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":\"0x" + "ab".repeat(32) + "\"}", TABLE));
        assertEquals("16", Web3Summary.resultNote(null, "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":\"0x10\"}", TABLE));
        assertEquals("null", Web3Summary.resultNote(null, "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":null}", TABLE));
        assertEquals("1 of 2 failed", Web3Summary.resultNote(null,
                "[{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"},{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":1}}]", TABLE));
        assertNull(Web3Summary.resultNote(null, "[{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"},{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":\"0x2\"}]", TABLE));
        assertNull(Web3Summary.resultNote(call, "<html>", TABLE));
        assertNull(Web3Summary.resultNote(call, null, TABLE));
    }

    private static String word(int value) {
        return String.format("%064x", value);
    }
}
