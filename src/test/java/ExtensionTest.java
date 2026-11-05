import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExtensionTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void exposesPayloadTamperingHelper() {
        assertTrue(Arrays.stream(Extension.class.getMethods())
                        .anyMatch(method -> method.getName().equals("tamperWeb3Payload")
                                && method.getReturnType() == String.class
                                && Arrays.equals(method.getParameterTypes(), new Class<?>[]{String.class})),
                "Extension must expose public String tamperWeb3Payload(String jsonBody)");
    }

    @Test
    void preservesNullBlankAndEmptyBodies() {
        Extension extension = new Extension();

        assertNull(extension.tamperWeb3Payload(null));
        for (String body : new String[]{"", " ", "\n\t\r "}) {
            assertEquals(body, extension.tamperWeb3Payload(body));
        }
    }

    @Test
    void preservesMalformedJsonAndRejectsAmbiguousDocuments() {
        RecordingExtension extension = new RecordingExtension();
        String call = callBody("data", "0x1234");
        String[] bodies = {
                "{",
                "[] trailing garbage",
                call + " {}",
                call + " null",
                "{\"jsonrpc\":\"2.0\",\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"data\":\"0x1234\"}]}",
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"data\":\"0x1234\",\"data\":\"0xabcd\"}]}",
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"data\":\"0x1234\"}],}"
        };

        for (String body : bodies) {
            assertEquals(body, extension.tamperWeb3Payload(body), body);
        }
        assertEquals(0, extension.callCount);
        assertEquals(0, extension.rawCount);
    }

    @Test
    void preservesScalarRootsAndEmptyBatches() {
        RecordingExtension extension = new RecordingExtension();
        for (String body : new String[]{"null", "true", "42", "\"eth_call\"", " [ ] "}) {
            assertEquals(body, extension.tamperWeb3Payload(body));
        }
        assertEquals(0, extension.callCount);
        assertEquals(0, extension.rawCount);
    }

    @Test
    void requiresAnExactJsonRpcVersionAndTargetMethod() {
        RecordingExtension extension = new RecordingExtension();
        String[] bodies = {
                "{\"method\":\"eth_call\",\"params\":[{\"data\":\"0x1234\"}]}",
                "{\"jsonrpc\":\"1.0\",\"method\":\"eth_call\",\"params\":[{\"data\":\"0x1234\"}]}",
                "{\"jsonrpc\":2.0,\"method\":\"eth_call\",\"params\":[{\"data\":\"0x1234\"}]}",
                "{\"jsonrpc\":null,\"method\":\"eth_call\",\"params\":[{\"data\":\"0x1234\"}]}",
                "{\"jsonrpc\":\"2.0\",\"method\":\"ETH_CALL\",\"params\":[{\"data\":\"0x1234\"}]}",
                "{\"jsonrpc\":\"2.0\",\"method\":\"eth_estimateGas\",\"params\":[{\"data\":\"0x1234\"}]}",
                "{\"jsonrpc\":\"2.0\",\"method\":null,\"params\":[{\"data\":\"0x1234\"}]}"
        };

        for (String body : bodies) {
            assertEquals(body, extension.tamperWeb3Payload(body), body);
        }
        assertEquals(0, extension.callCount);
        assertEquals(0, extension.rawCount);
    }

    @Test
    void preservesOriginalFormattingWhenHooksDoNotChangeParameters() {
        RecordingExtension extension = new RecordingExtension();
        String body = "  {\n  \"id\" : 7, \"jsonrpc\" : \"2.0\", \"method\" : \"eth_call\",\n"
                + "  \"params\" : [ { \"data\" : \"0x1234\", \"to\" : \"0xabc\" }, \"latest\" ]\n}  ";

        assertEquals(body, extension.tamperWeb3Payload(body));
        assertEquals(1, extension.callCount);
        assertEquals(0, extension.rawCount);
    }

    @Test
    void acceptsDataAndInputAliasesIncludingEmptyHexPayloads() {
        RecordingExtension extension = new RecordingExtension();
        for (String field : new String[]{"data", "input"}) {
            for (String payload : new String[]{"0x", "0x00", "0xabcdef", "0xAbCdEF"}) {
                String body = callBody(field, payload);
                assertEquals(body, extension.tamperWeb3Payload(body));
            }
        }
        assertEquals(8, extension.callCount);
    }

    @Test
    void skipsCallsWithoutValidHexDataOrInput() {
        RecordingExtension extension = new RecordingExtension();
        for (String payload : new String[]{"", "1234", "0X1234", "0x1", "0xxyz0", "0x 12", "0x１２"}) {
            for (String field : new String[]{"data", "input"}) {
                String body = callBody(field, payload);
                assertEquals(body, extension.tamperWeb3Payload(body), body);
            }
        }
        for (String params : new String[]{"null", "[]", "{}", "[null]", "[\"0x1234\"]", "[{}]",
                "[{\"data\":null}]", "[{\"data\":1234}]", "[{\"data\":[]}]"}) {
            String body = rpcBody("eth_call", params);
            assertEquals(body, extension.tamperWeb3Payload(body), body);
        }
        assertEquals(0, extension.callCount);
        assertEquals(0, extension.rawCount);
    }

    @Test
    void callMutationPreservesRpcEnvelopeOtherParametersAndTransactionFields() throws Exception {
        MutatingExtension extension = new MutatingExtension();
        String body = "{\"jsonrpc\":\"2.0\",\"id\":\"report-9\",\"method\":\"eth_call\","
                + "\"params\":[{\"data\":\"0x1234\",\"to\":\"0xabc\",\"value\":\"0x1\"},"
                + "\"pending\",{\"0xdef\":{\"balance\":\"0x2\"}}],\"extensionField\":true}";

        String result = extension.tamperWeb3Payload(body);
        JsonNode expected = JSON.readTree(body);
        ((ObjectNode) expected.path("params").get(0)).put("data", "0xaabb");

        assertNotEquals(body, result);
        assertEquals(expected, JSON.readTree(result));
        assertEquals(1, extension.callCount);
        assertEquals(0, extension.rawCount);
    }

    @Test
    void inputMutationUsesTheInputField() throws Exception {
        MutatingExtension extension = new MutatingExtension();

        JsonNode result = JSON.readTree(extension.tamperWeb3Payload(callBody("input", "0x1234")));

        assertEquals("0xaabb", result.path("params").get(0).path("input").asText());
        assertTrue(result.path("params").get(0).path("data").isMissingNode());
        assertEquals(1, extension.callCount);
    }

    @Test
    void rawTransactionHookTargetsTheFirstStringParameter() throws Exception {
        MutatingExtension extension = new MutatingExtension();
        String body = "{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"eth_sendRawTransaction\","
                + "\"params\":[\"0x1234\",{\"keep\":\"this\"}]}";

        String result = extension.tamperWeb3Payload(body);
        JsonNode expected = JSON.readTree(body);
        ((com.fasterxml.jackson.databind.node.ArrayNode) expected.path("params")).set(0, JSON.getNodeFactory().textNode("0xccdd"));

        assertEquals(expected, JSON.readTree(result));
        assertEquals(0, extension.callCount);
        assertEquals(1, extension.rawCount);
    }

    @Test
    void preservesOriginalRawTransactionBodyWhenTheHookIsANoOp() {
        RecordingExtension extension = new RecordingExtension();
        String body = "\n{ \"method\" : \"eth_sendRawTransaction\", \"jsonrpc\" : \"2.0\",\n"
                + "\"params\" : [ \"0xABcd\" ], \"id\" : null }\n";

        assertEquals(body, extension.tamperWeb3Payload(body));
        assertEquals(1, extension.rawCount);
    }

    @Test
    void skipsInvalidRawTransactionsAndUnexpectedParameterShapes() {
        RecordingExtension extension = new RecordingExtension();
        for (String params : new String[]{"null", "[]", "{}", "[null]", "[{}]", "[1234]",
                "[\"\"]", "[\"1234\"]", "[\"0X1234\"]", "[\"0x1\"]", "[\"0xzz\"]"}) {
            String body = rpcBody("eth_sendRawTransaction", params);
            assertEquals(body, extension.tamperWeb3Payload(body), body);
        }
        assertEquals(0, extension.callCount);
        assertEquals(0, extension.rawCount);
    }

    @Test
    void targetsOnlyMatchingEntriesWithinMixedBatches() throws Exception {
        MutatingExtension extension = new MutatingExtension();
        String otherRpc = rpcBody("eth_estimateGas", "[{\"data\":\"0x1234\"}]");
        String invalidTarget = rpcBody("eth_call", "[{}]");
        String body = "[" + callBody("data", "0x1234") + "," + otherRpc
                + ",null,42," + rpcBody("eth_sendRawTransaction", "[\"0x1234\"]") + "," + invalidTarget + "]";

        JsonNode result = JSON.readTree(extension.tamperWeb3Payload(body));
        JsonNode original = JSON.readTree(body);

        assertEquals("0xaabb", result.get(0).path("params").get(0).path("data").asText());
        assertEquals(original.get(1), result.get(1));
        assertEquals(original.get(2), result.get(2));
        assertEquals(original.get(3), result.get(3));
        assertEquals("0xccdd", result.get(4).path("params").get(0).asText());
        assertEquals(original.get(5), result.get(5));
        assertEquals(1, extension.callCount);
        assertEquals(1, extension.rawCount);
    }

    @Test
    void preservesFormattingForAnUnmodifiedBatch() {
        RecordingExtension extension = new RecordingExtension();
        String body = "\n[ " + callBody("data", "0x1234") + ",\n "
                + rpcBody("eth_sendRawTransaction", "[\"0x1234\"]") + " ]\t";

        assertEquals(body, extension.tamperWeb3Payload(body));
        assertEquals(1, extension.callCount);
        assertEquals(1, extension.rawCount);
    }

    @Test
    void supportsNotificationsWithoutAddingAnId() throws Exception {
        MutatingExtension extension = new MutatingExtension();
        String body = rpcBody("eth_call", "[{\"data\":\"0x1234\"}]");

        JsonNode result = JSON.readTree(extension.tamperWeb3Payload(body));

        assertTrue(result.path("id").isMissingNode());
        assertEquals("0xaabb", result.path("params").get(0).path("data").asText());
    }

    @Test
    void callHookFailurePreservesTheEntireOriginalBody() {
        Extension extension = new Extension() {
            @Override
            protected void tamperCall(ObjectNode transaction) {
                transaction.put("data", "0xaabb");
                throw new IllegalStateException("test fuzz hook failed");
            }
        };
        String body = "\n " + callBody("data", "0x1234") + " \t";

        assertEquals(body, extension.tamperWeb3Payload(body));
    }

    @Test
    void rawTransactionHookFailurePreservesTheEntireOriginalBody() {
        Extension extension = new Extension() {
            @Override
            protected String tamperRawTransaction(String signedTransactionHex) {
                throw new IllegalArgumentException("test raw transaction hook failed");
            }
        };
        String body = rpcBody("eth_sendRawTransaction", "[\"0x1234\"]");

        assertEquals(body, extension.tamperWeb3Payload(body));
    }

    @Test
    void failureInALaterBatchEntryRollsBackEarlierMutations() {
        Extension extension = new Extension() {
            private int calls;

            @Override
            protected void tamperCall(ObjectNode transaction) {
                if (++calls == 2) {
                    throw new IllegalStateException("second batch entry failed");
                }
                transaction.put("data", "0xaabb");
            }
        };
        String body = "  [\n" + callBody("data", "0x1234") + ", " + callBody("data", "0x5678") + "\n] ";

        assertEquals(body, extension.tamperWeb3Payload(body));
    }

    @Test
    void skipsBodiesExceedingTheUtf8ByteLimitBeforeInvokingHooks() {
        MutatingExtension extension = new MutatingExtension();
        String body = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"data\":\"0x1234\"}],"
                + "\"note\":\"" + "😀".repeat(262_144) + "\"}";
        assertTrue(body.length() < 1_048_576, "This case distinguishes character count from UTF-8 byte count");
        assertTrue(body.getBytes(StandardCharsets.UTF_8).length > 1_048_576);

        assertEquals(body, extension.tamperWeb3Payload(body));
        assertEquals(0, extension.callCount);
    }

    @Test
    void supportsTheMaximumBatchSize() throws Exception {
        MutatingExtension extension = new MutatingExtension();
        String body = "[" + String.join(",", Collections.nCopies(256, callBody("data", "0x1234"))) + "]";

        JsonNode result = JSON.readTree(extension.tamperWeb3Payload(body));

        assertEquals(256, result.size());
        assertEquals(256, extension.callCount);
        for (JsonNode entry : result) {
            assertEquals("0xaabb", entry.path("params").get(0).path("data").asText());
        }
    }

    @Test
    void skipsBatchesExceedingTheEntryLimitBeforeInvokingHooks() {
        MutatingExtension extension = new MutatingExtension();
        String body = "[" + String.join(",", Collections.nCopies(257, callBody("data", "0x1234"))) + "]";

        assertEquals(body, extension.tamperWeb3Payload(body));
        assertEquals(0, extension.callCount);
    }

    private static String callBody(String field, String payload) {
        return rpcBody("eth_call", "[{\"" + field + "\":\"" + payload + "\"},\"latest\"]");
    }

    private static String rpcBody(String method, String params) {
        return "{\"jsonrpc\":\"2.0\",\"method\":\"" + method + "\",\"params\":" + params + "}";
    }

    private static class RecordingExtension extends Extension {
        int callCount;
        int rawCount;

        @Override
        protected void tamperCall(ObjectNode transaction) {
            callCount++;
        }

        @Override
        protected String tamperRawTransaction(String signedTransactionHex) {
            rawCount++;
            return signedTransactionHex;
        }
    }

    private static class MutatingExtension extends RecordingExtension {
        @Override
        protected void tamperCall(ObjectNode transaction) {
            super.tamperCall(transaction);
            transaction.put(transaction.has("data") ? "data" : "input", "0xaabb");
        }

        @Override
        protected String tamperRawTransaction(String signedTransactionHex) {
            super.tamperRawTransaction(signedTransactionHex);
            return "0xccdd";
        }
    }
}
