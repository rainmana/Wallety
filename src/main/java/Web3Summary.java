import burp.api.montoya.core.HighlightColor;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Read-only description of a JSON-RPC request body for history notes and the editor tab. */
final class Web3Summary {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Set<String> TX_OBJECT_METHODS = Set.of(
            "eth_call", "eth_estimateGas", "eth_sendTransaction", "eth_createAccessList", "debug_traceCall");
    private static final Set<String> SENSITIVE_METHODS = Set.of(
            "eth_sendTransaction", "eth_sendRawTransaction", "eth_sign", "personal_sign",
            "eth_signTransaction", "eth_signTypedData", "eth_signTypedData_v3", "eth_signTypedData_v4",
            "wallet_sendCalls", "eth_sendBundle");
    private static final int MAX_NOTE = 200;
    private static final int MAX_PARAMS_PREVIEW = 4000;
    private static final BigDecimal WEI_PER_ETHER = new BigDecimal("1000000000000000000");

    final String note;
    final HighlightColor highlight;
    final String detail;

    private Web3Summary(String note, HighlightColor highlight, String detail) {
        this.note = note;
        this.highlight = highlight;
        this.detail = detail;
    }

    /** Null when the body is not a JSON-RPC 2.0 request or batch. Never throws. */
    static Web3Summary describe(String body, Map<String, String> selectors) {
        List<JsonNode> rpcs = rpcNodes(body);
        if (rpcs.isEmpty()) {
            return null;
        }

        StringBuilder detail = new StringBuilder();
        List<String> noteParts = new ArrayList<>();
        HighlightColor highlight = HighlightColor.NONE;
        for (int i = 0; i < rpcs.size(); i++) {
            JsonNode rpc = rpcs.get(i);
            String method = rpc.path("method").asText("?");
            if (SENSITIVE_METHODS.contains(method)) {
                highlight = HighlightColor.ORANGE;
            }
            if (rpcs.size() > 1) {
                detail.append("[").append(i).append("] ");
            }
            noteParts.add(describeOne(rpc, method, selectors, detail));
            if (i < rpcs.size() - 1) {
                detail.append('\n');
            }
        }

        String note;
        if (rpcs.size() == 1) {
            note = noteParts.get(0);
        } else {
            Map<String, Integer> counts = new LinkedHashMap<>();
            for (JsonNode rpc : rpcs) {
                counts.merge(rpc.path("method").asText("?"), 1, Integer::sum);
            }
            StringBuilder sb = new StringBuilder("batch[" + rpcs.size() + "]:");
            counts.forEach((m, c) -> sb.append(' ').append(m).append(c > 1 ? "x" + c : ""));
            note = sb.toString();
        }
        if (note.length() > MAX_NOTE) {
            note = note.substring(0, MAX_NOTE - 1) + "…";
        }
        return new Web3Summary(note, highlight, detail.toString());
    }

    /** Appends the detail block for one RPC and returns its one-line note. */
    private static String describeOne(JsonNode rpc, String method, Map<String, String> selectors, StringBuilder out) {
        JsonNode id = rpc.get("id");
        out.append(method).append(id == null ? "  (notification)" : "  (id " + id + ")").append('\n');
        JsonNode params = rpc.path("params");
        JsonNode first = params.path(0);

        if (TX_OBJECT_METHODS.contains(method) && first.isObject()) {
            String to = first.path("to").asText(null);
            String from = first.path("from").asText(null);
            String value = first.path("value").asText(null);
            String data = first.hasNonNull("data") ? first.path("data").asText() : first.path("input").asText(null);
            if (from != null) {
                out.append("  from:   ").append(from).append('\n');
            }
            out.append("  to:     ").append(to == null ? "(contract creation)" : to).append('\n');
            if (value != null) {
                out.append("  value:  ").append(value).append("  ").append(formatWei(value)).append('\n');
            }
            if (params.size() > 1 && !params.get(1).isObject()) {
                out.append("  block:  ").append(params.get(1)).append('\n');
            }
            String call = method;
            if (data != null) {
                List<String> lines = Abi.describeCalldata(data, selectors);
                for (String line : lines) {
                    out.append("  ").append(line).append('\n');
                }
                String label = Abi.callLabel(lines);
                call += " " + (label == null ? "(no calldata)" : label);
            } else {
                out.append("  data:   none\n");
            }
            return call + (to == null ? "" : " → " + shorten(to));
        }

        if (method.equals("eth_sendRawTransaction") && first.isTextual()) {
            byte[] raw;
            try {
                raw = Abi.fromHex(first.asText());
            } catch (RuntimeException e) {
                out.append("  raw:      not valid hex\n");
                return method;
            }
            Rlp.Described tx = Rlp.describeTransaction(raw, selectors);
            for (String line : tx.lines) {
                out.append("  ").append(line).append('\n');
            }
            return method + " " + tx.label;
        }

        String preview = params.isMissingNode() ? "none" : params.toString();
        if (preview.length() > MAX_PARAMS_PREVIEW) {
            preview = preview.substring(0, MAX_PARAMS_PREVIEW) + "…";
        }
        out.append("  params: ").append(preview).append('\n');
        return method;
    }

    /**
     * Detail text for a JSON-RPC response, matched to its request by id so eth_call
     * results decode with the called function's return types. Null unless the
     * response is a JSON-RPC 2.0 result/error or batch of them. Never throws.
     */
    static String describeResponse(String requestBody, String responseBody, Map<String, String> selectors) {
        List<JsonNode> responses = rpcNodes(responseBody);
        if (responses.isEmpty()) {
            return null;
        }
        Map<String, JsonNode> requests = new LinkedHashMap<>();
        for (JsonNode rpc : rpcNodes(requestBody)) {
            requests.putIfAbsent(String.valueOf(rpc.get("id")), rpc);
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < responses.size(); i++) {
            JsonNode response = responses.get(i);
            JsonNode request = requests.get(String.valueOf(response.get("id")));
            String method = request == null ? "?" : request.path("method").asText("?");
            if (responses.size() > 1) {
                out.append("[").append(i).append("] ");
            }
            out.append(method).append("  (id ").append(response.get("id")).append(")\n");
            JsonNode error = response.get("error");
            if (error != null) {
                out.append("  error:  ").append(error.path("code")).append("  ").append(error.path("message")).append('\n');
                if (error.path("data").isTextual() && error.path("data").asText().startsWith("0x")) {
                    // Revert data is ABI-encoded like calldata: Error(string), Panic(uint256), custom errors.
                    for (String line : Abi.describeCalldata(error.path("data").asText(), selectors)) {
                        out.append("  ").append(line).append('\n');
                    }
                } else if (error.has("data")) {
                    out.append("  data:   ").append(error.get("data")).append('\n');
                }
            } else if (method.equals("eth_call") && response.path("result").isTextual()) {
                for (String line : Abi.describeReturn(response.path("result").asText(), requestSignature(request, selectors))) {
                    out.append("  ").append(line).append('\n');
                }
            } else {
                String result = response.path("result").toString();
                if (result.length() > MAX_PARAMS_PREVIEW) {
                    result = result.substring(0, MAX_PARAMS_PREVIEW) + "…";
                }
                out.append("  result: ").append(result);
                String text = response.path("result").asText("");
                if (text.matches("0x[0-9a-fA-F]{1,64}") && !method.endsWith("Hash") && text.length() < 50) {
                    out.append("  = ").append(new BigInteger(text.substring(2), 16));
                    if (method.equals("eth_getBalance")) {
                        out.append("  ").append(formatWei(text));
                    }
                }
                out.append('\n');
            }
            if (i < responses.size() - 1) {
                out.append('\n');
            }
        }
        return out.toString();
    }

    private static List<JsonNode> rpcNodes(String body) {
        List<JsonNode> rpcs = new ArrayList<>();
        if (body == null || !body.contains("\"jsonrpc\"")) {
            return rpcs;
        }
        JsonNode root;
        try {
            root = JSON.readTree(body);
        } catch (java.io.IOException | RuntimeException e) {
            return rpcs;
        }
        if (root != null && root.isArray()) {
            root.forEach(rpcs::add);
        } else if (root != null) {
            rpcs.add(root);
        }
        rpcs.removeIf(n -> !n.isObject() || !"2.0".equals(n.path("jsonrpc").asText(null)));
        return rpcs;
    }

    /** Full signature (with return types if known) of the function an eth_call request invokes. */
    private static String requestSignature(JsonNode request, Map<String, String> selectors) {
        JsonNode tx = request == null ? null : request.path("params").path(0);
        if (tx == null || !tx.isObject()) {
            return null;
        }
        String data = tx.hasNonNull("data") ? tx.path("data").asText() : tx.path("input").asText("");
        return data.length() >= 10 ? selectors.get(data.substring(2, 10).toLowerCase(java.util.Locale.ROOT)) : null;
    }

    static String formatWei(String hexOrDecimal) {
        try {
            BigInteger wei = hexOrDecimal.startsWith("0x")
                    ? new BigInteger(hexOrDecimal.substring(2), 16) : new BigInteger(hexOrDecimal);
            return "(" + wei + " wei = " + new BigDecimal(wei).divide(WEI_PER_ETHER).stripTrailingZeros().toPlainString() + " ether)";
        } catch (RuntimeException e) {
            return "(unparseable)";
        }
    }

    static String shorten(String address) {
        return address.length() > 12 ? address.substring(0, 6) + "…" + address.substring(address.length() - 4) : address;
    }
}
