import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.settings.SettingsPanelBuilder;
import burp.api.montoya.ui.settings.SettingsPanelPersistence;
import burp.api.montoya.ui.settings.SettingsPanelSetting;
import burp.api.montoya.ui.settings.SettingsPanelWithData;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.awt.Component;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Ethereum JSON-RPC visibility for Burp: history notes and highlights, a
 * decoded "Web3" editor tab, and no-op tamper hooks on the send path.
 * No network calls, key handling, or transaction signing occur.
 */
public class Extension implements BurpExtension, HttpHandler {
    static final String SIGNATURES_SETTING = "Extra function signatures";

    // Bound parser work on the Proxy thread. Raise these for larger RPC batches.
    private static final int MAX_BODY_BYTES = 1024 * 1024;
    private static final int MAX_BATCH_ENTRIES = 256;
    private static final long ERROR_LOG_INTERVAL_NANOS = 5_000_000_000L;

    // Configured once, then used concurrently. JSON trees remain request-local.
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(64)
                    .maxStringLength(MAX_BODY_BYTES)
                    .maxNumberLength(128)
                    .build())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS)
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    private final AtomicLong nextErrorLogAt = new AtomicLong();
    private volatile MontoyaApi montoya;
    private volatile SettingsPanelWithData settings;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoya = Objects.requireNonNull(montoyaApi, "Montoya API");
        montoya.extension().setName("Wallety - Web3 JSON-RPC");
        settings = SettingsPanelBuilder.settingsPanel()
                .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
                .withTitle("Wallety")
                .withDescription("Function signatures to decode in addition to the bundled list, "
                        + "separated by spaces, e.g. swap(address,uint256) claim(uint256[])")
                .withKeywords("web3", "ethereum", "abi")
                .withSettings(SettingsPanelSetting.stringSetting(SIGNATURES_SETTING, ""))
                .build();
        montoya.userInterface().registerSettingsPanel(settings);
        montoya.userInterface().registerHttpRequestEditorProvider(context -> new RequestTab());
        montoya.userInterface().registerHttpResponseEditorProvider(context -> new ResponseTab());
        montoya.http().registerHttpHandler(this);
        // No threads or sockets to release; Burp drops registrations itself.
        montoya.extension().registerUnloadingHandler(() -> logOutput("{\"event\":\"web3_extension_unloaded\"}"));
        logOutput("{\"event\":\"web3_extension_loaded\",\"coverage\":\"all Burp tools\","
                + "\"tampering\":\"no-op until hooks are customized\"}");
    }

    Map<String, String> selectors() {
        SettingsPanelWithData panel = settings;
        String extra = null;
        if (panel != null) {
            try {
                extra = panel.getString(SIGNATURES_SETTING);
            } catch (RuntimeException ignored) {
                // Settings unavailable: fall back to the bundled table.
            }
        }
        return Abi.table(extra);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        HttpRequest outgoing = request;
        String finalBody = null;
        List<ObjectNode> reports = new ArrayList<>();
        try {
            String original = bodyText(request);
            if (original == null) {
                return RequestToBeSentAction.continueWith(request, request.annotations());
            }
            finalBody = tamperWeb3Payload(original, reports);
            if (!original.equals(finalBody)) {
                // Montoya updates Content-Length from the actual body bytes.
                outgoing = request.withBody(ByteArray.byteArray(
                        finalBody.getBytes(StandardCharsets.UTF_8)));
            }
        } catch (RuntimeException exception) {
            reports.clear();
            logFailure("request_preparation", exception);
            outgoing = request;
        }

        // Build the action before reporting success. An API failure must not
        // produce a log claiming that a changed body was prepared for forwarding.
        RequestToBeSentAction action;
        try {
            action = RequestToBeSentAction.continueWith(outgoing, annotate(request.annotations(), finalBody));
        } catch (RuntimeException exception) {
            reports.clear();
            logFailure("forwarding_action", exception);
            return RequestToBeSentAction.continueWith(request, request.annotations());
        }
        logReports(reports, request);
        return action;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            Annotations annotations = response.annotations();
            String requestBody = bodyText(response.initiatingRequest());
            Web3Summary summary = requestBody == null ? null : Web3Summary.describe(requestBody, selectors());
            // Only extend the note this extension wrote at request time; never touch a user's own.
            if (summary != null && annotations.hasNotes() && summary.note.equals(annotations.notes())) {
                String result = Web3Summary.resultNote(requestBody, bodyText(response), selectors());
                if (result != null) {
                    return ResponseReceivedAction.continueWith(response,
                            annotations.withNotes(summary.note + "  = " + result));
                }
            }
        } catch (RuntimeException exception) {
            logFailure("response_annotation", exception);
        }
        return ResponseReceivedAction.continueWith(response);
    }

    /** Adds a note and highlight for Web3 traffic without clobbering user-written ones. */
    private Annotations annotate(Annotations annotations, String body) {
        Web3Summary summary = body == null ? null : Web3Summary.describe(body, selectors());
        if (summary == null) {
            return annotations;
        }
        if (!annotations.hasNotes()) {
            annotations = annotations.withNotes(summary.note);
        }
        if (!annotations.hasHighlightColor() && summary.highlight != HighlightColor.NONE) {
            annotations = annotations.withHighlightColor(summary.highlight);
        }
        return annotations;
    }

    /** Strict UTF-8 body text, or null when absent, too large, encoded, or not UTF-8. */
    static String bodyText(HttpMessage message) {
        ByteArray body = message == null ? null : message.body();
        // Encoded or chunk-framed bodies need a separate decoding pipeline.
        if (body == null || body.length() == 0 || body.length() > MAX_BODY_BYTES
                || hasEncodedBody(message)) {
            return null;
        }
        try {
            // JSON-RPC over HTTP is UTF-8; do not use Burp's configurable charset.
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(body.getBytes())).toString();
        } catch (CharacterCodingException exception) {
            return null;
        }
    }

    /** Read-only "Web3" tab shared by the request and response editors. */
    private abstract class Tab implements ExtensionProvidedEditor {
        final RawEditor editor = montoya.userInterface().createRawEditor(EditorOptions.READ_ONLY);
        HttpRequestResponse current;

        /** Decoded text for the message, or null when the tab should be hidden. */
        abstract String decode(HttpRequestResponse requestResponse);

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            current = requestResponse;
            String text = text(requestResponse);
            editor.setContents(ByteArray.byteArray((text == null ? "" : text).getBytes(StandardCharsets.UTF_8)));
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            return text(requestResponse) != null;
        }

        private String text(HttpRequestResponse requestResponse) {
            try {
                return requestResponse == null ? null : decode(requestResponse);
            } catch (RuntimeException exception) {
                logFailure("editor_tab", exception);
                return null;
            }
        }

        @Override
        public String caption() {
            return "Web3";
        }

        @Override
        public Component uiComponent() {
            return editor.uiComponent();
        }

        @Override
        public Selection selectedData() {
            return editor.selection().orElse(null);
        }

        @Override
        public boolean isModified() {
            return false;
        }
    }

    private final class RequestTab extends Tab implements ExtensionProvidedHttpRequestEditor {
        @Override
        String decode(HttpRequestResponse requestResponse) {
            Web3Summary summary = Web3Summary.describe(bodyText(requestResponse.request()), selectors());
            return summary == null ? null : summary.detail;
        }

        @Override
        public HttpRequest getRequest() {
            return current == null ? null : current.request();
        }
    }

    private final class ResponseTab extends Tab implements ExtensionProvidedHttpResponseEditor {
        @Override
        String decode(HttpRequestResponse requestResponse) {
            return Web3Summary.describeResponse(bodyText(requestResponse.request()),
                    bodyText(requestResponse.response()), selectors());
        }

        @Override
        public HttpResponse getResponse() {
            return current == null ? null : current.response();
        }
    }

    /**
     * Parse, tamper, and serialize one JSON-RPC request or a batch. Malformed,
     * unsupported, and unchanged input is returned verbatim (including null).
     * This entry point also works without Burp for unit testing or reuse.
     */
    public String tamperWeb3Payload(String jsonBody) {
        return tamperWeb3Payload(jsonBody, new ArrayList<>());
    }

    private String tamperWeb3Payload(String jsonBody, List<ObjectNode> reports) {
        // The cheap key check accepts ordinary whitespace around ':' and avoids
        // parsing unrelated traffic. The parsed top-level RPC version is decisive.
        if (jsonBody == null || jsonBody.isBlank()
                || jsonBody.length() > MAX_BODY_BYTES
                || !jsonBody.contains("\"jsonrpc\"")
                || jsonBody.getBytes(StandardCharsets.UTF_8).length > MAX_BODY_BYTES) {
            return jsonBody;
        }
        try {
            JsonNode root = JSON.readTree(jsonBody);
            boolean changed = false;
            if (root instanceof ObjectNode rpc) {
                changed = tamperRpc(rpc, -1, reports);
            } else if (root instanceof ArrayNode batch) {
                if (batch.isEmpty() || batch.size() > MAX_BATCH_ENTRIES) {
                    return jsonBody;
                }
                for (int index = 0; index < batch.size(); index++) {
                    if (batch.get(index) instanceof ObjectNode rpc) {
                        changed |= tamperRpc(rpc, index, reports);
                    }
                }
            }
            if (!changed) {
                return jsonBody;
            }
            String modified = JSON.writeValueAsString(root);
            if (modified.length() > MAX_BODY_BYTES
                    || modified.getBytes(StandardCharsets.UTF_8).length > MAX_BODY_BYTES) {
                throw new IllegalArgumentException("Tampered body exceeds byte limit");
            }
            return modified;
        } catch (IOException | RuntimeException exception) {
            // Roll back the entire body, including any earlier batch mutations.
            reports.clear();
            logFailure("payload_tampering", exception);
            return jsonBody;
        }
    }

    private boolean tamperRpc(ObjectNode rpc, int batchIndex, List<ObjectNode> reports) {
        if (!isText(rpc.get("jsonrpc"), "2.0")) {
            return false;
        }
        String method = rpc.path("method").isTextual() ? rpc.get("method").textValue() : "";
        if (!method.equals("eth_call") && !method.equals("eth_sendRawTransaction")) {
            return false;
        }

        JsonNode originalParams = rpc.has("params")
                ? rpc.get("params").deepCopy() : NullNode.getInstance();
        String status = "skipped_invalid_params";
        if (rpc.get("params") instanceof ArrayNode params && !params.isEmpty()) {
            if (method.equals("eth_call") && params.get(0) instanceof ObjectNode transaction
                    && hasHexCalldata(transaction)) {
                tamperCall(transaction);
                status = "observed";
            } else if (method.equals("eth_sendRawTransaction") && isHexData(params.get(0))) {
                String signedTransaction = params.get(0).textValue();
                String modified = Objects.requireNonNull(tamperRawTransaction(signedTransaction),
                        "Raw transaction hook returned null");
                params.set(0, JSON.getNodeFactory().textNode(modified));
                status = "observed";
            }
        }

        JsonNode finalParams = rpc.has("params") ? rpc.get("params") : NullNode.getInstance();
        boolean changed = !originalParams.equals(finalParams);
        ObjectNode report = JSON.createObjectNode();
        report.put("event", "web3_rpc");
        report.put("method", method);
        report.set("rpc_id", rpc.has("id") ? rpc.get("id").deepCopy() : NullNode.getInstance());
        report.put("notification", !rpc.has("id"));
        report.put("batch_index", batchIndex); // -1 denotes a standalone request.
        report.put("status", changed ? "modified" : status);
        report.put("parameters_modified", changed);
        report.put("params_present", rpc.has("params"));
        report.set("params_before", originalParams);
        report.set("params_after", finalParams.deepCopy());
        reports.add(report);
        return changed;
    }

    /** Customize this hook for eth_call; edits apply to params[0] only. */
    protected void tamperCall(ObjectNode transaction) {
        String field = transaction.has("data") ? "data" : "input";
        String originalHex = transaction.get(field).textValue();

        // FUZZING / ADDRESS-TAMPERING PLACEHOLDER:
        // String modifiedHex = yourCalldataFuzzer(originalHex);
        // transaction.put(field, modifiedHex);
        // transaction.put("to", "0x...your authorized test contract address...");
        // If both data and input exist, keep them consistent for your target node.
        // Preserve the block selector and all other params unless intentional.
    }

    /** Customize separately: params[0] is a whole signed transaction, not data. */
    protected String tamperRawTransaction(String signedTransactionHex) {
        // RAW-TRANSACTION FUZZING PLACEHOLDER:
        // Return mutated bytes here to test malformed-transaction validation.
        // To change calldata or addresses while retaining the intended sender,
        // decode the transaction and re-sign it with an authorized test key.
        return signedTransactionHex;
    }

    private static boolean hasHexCalldata(ObjectNode transaction) {
        boolean present = false;
        for (String field : List.of("data", "input")) {
            if (transaction.has(field)) {
                if (!isHexData(transaction.get(field))) {
                    return false;
                }
                present = true;
            }
        }
        return present;
    }

    private static boolean isText(JsonNode node, String expected) {
        return node != null && node.isTextual() && expected.equals(node.textValue());
    }

    private static boolean isHexData(JsonNode node) {
        if (node == null || !node.isTextual()) {
            return false;
        }
        String hex = node.textValue();
        if (!hex.startsWith("0x") || (hex.length() & 1) != 0) {
            return false;
        }
        for (int index = 2; index < hex.length(); index++) {
            char character = hex.charAt(index);
            if (!((character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f')
                    || (character >= 'A' && character <= 'F'))) {
                return false;
            }
        }
        return true; // "0x" is valid empty calldata; this is not RLP validation.
    }

    private static boolean hasEncodedBody(HttpMessage message) {
        if (message.hasHeader("Transfer-Encoding")) {
            return true;
        }
        String encoding = message.headerValue("Content-Encoding");
        if (encoding == null || encoding.isBlank()) {
            return false;
        }
        for (String token : encoding.split(",")) {
            if (!token.trim().equalsIgnoreCase("identity")) {
                return true;
            }
        }
        return false;
    }

    private void logReports(List<ObjectNode> reports, HttpRequestToBeSent request) {
        for (ObjectNode report : reports) {
            try {
                report.put("timestamp_utc", Instant.now().toString());
                report.put("http_message_id", request.messageId());
                report.put("http_method", request.method());
                report.put("url", request.url());
                // One escaped JSON record per RPC: concurrent records stay intact
                // and untrusted strings cannot inject fake log lines.
                logOutput(JSON.writeValueAsString(report));
            } catch (IOException | RuntimeException exception) {
                logFailure("report_serialization", exception);
            }
        }
    }

    private void logOutput(String message) {
        MontoyaApi api = montoya;
        if (api != null) {
            try {
                api.logging().logToOutput(message);
            } catch (RuntimeException ignored) {
                // Logging failure must never change forwarding behavior.
            }
        }
    }

    private void logFailure(String stage, Exception exception) {
        long now = System.nanoTime();
        long next = nextErrorLogAt.get();
        if (now - next >= 0 && nextErrorLogAt.compareAndSet(next, now + ERROR_LOG_INTERVAL_NANOS)) {
            // No exception message/body dump: avoid accidental credential leakage.
            logOutput("{\"event\":\"web3_passthrough_error\",\"stage\":\"" + stage
                    + "\",\"error_type\":\"" + exception.getClass().getSimpleName()
                    + "\",\"action\":\"original_request_preserved\"}");
        }
    }
}
