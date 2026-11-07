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
        if (body == null || !body.contains("\"jsonrpc\"")) {
            return null;
        }
        JsonNode root;
        try {
            root = JSON.readTree(body);
        } catch (java.io.IOException | RuntimeException e) {
            return null;
        }
        List<JsonNode> rpcs = new ArrayList<>();
        if (root != null && root.isArray()) {
            root.forEach(rpcs::add);
        } else if (root != null) {
            rpcs.add(root);
        }
        rpcs.removeIf(n -> !n.isObject() || !"2.0".equals(n.path("jsonrpc").asText(null)));
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
                String head = lines.get(0);
                if (head.startsWith("selector ")) {
                    String signature = head.substring("selector 0x".length() + 8).strip();
                    call += " " + (signature.startsWith("(unknown") ? head.substring(9, 19) : signature.substring(0, signature.indexOf('(')));
                } else {
                    call += " (no calldata)";
                }
            } else {
                out.append("  data:   none\n");
            }
            return call + (to == null ? "" : " → " + shorten(to));
        }

        if (method.equals("eth_sendRawTransaction") && first.isTextual()) {
            String hex = first.asText();
            byte[] raw;
            try {
                raw = Abi.fromHex(hex);
            } catch (RuntimeException e) {
                out.append("  raw:    not valid hex\n");
                return method;
            }
            // ponytail: envelope type only; RLP decode and sender recovery come later.
            String kind = raw.length == 0 ? "empty" : switch (raw[0] & 0xff) {
                case 0x01 -> "EIP-2930 (type 1)";
                case 0x02 -> "EIP-1559 (type 2)";
                case 0x03 -> "EIP-4844 blob (type 3)";
                case 0x04 -> "EIP-7702 set-code (type 4)";
                default -> (raw[0] & 0xff) >= 0xc0 ? "legacy (RLP list)" : "unknown type 0x" + Keccak.hex(raw, 1);
            };
            out.append("  raw:    ").append(raw.length).append(" bytes, ").append(kind).append('\n');
            return method + " " + kind;
        }

        String preview = params.isMissingNode() ? "none" : params.toString();
        if (preview.length() > MAX_PARAMS_PREVIEW) {
            preview = preview.substring(0, MAX_PARAMS_PREVIEW) + "…";
        }
        out.append("  params: ").append(preview).append('\n');
        return method;
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
