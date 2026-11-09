import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** RLP decoding and signed-transaction field layouts (legacy and EIP-2718 types 1-4). */
final class Rlp {
    private static final int MAX_LIST_PREVIEW = 16;
    private static final BigDecimal WEI_PER_GWEI = new BigDecimal("1000000000");

    private static final String[] LEGACY = {"nonce", "gasPrice", "gasLimit", "to", "value", "data", "v", "r", "s"};
    private static final String[] TYPE1 = {"chainId", "nonce", "gasPrice", "gasLimit", "to", "value", "data",
            "accessList", "yParity", "r", "s"};
    private static final String[] TYPE2 = {"chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit",
            "to", "value", "data", "accessList", "yParity", "r", "s"};
    private static final String[] TYPE3 = {"chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit",
            "to", "value", "data", "accessList", "maxFeePerBlobGas", "blobVersionedHashes", "yParity", "r", "s"};
    private static final String[] TYPE4 = {"chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit",
            "to", "value", "data", "accessList", "authorizationList", "yParity", "r", "s"};

    private Rlp() {
    }

    static final class Item {
        final byte[] bytes;
        final List<Item> list;

        Item(byte[] bytes, List<Item> list) {
            this.bytes = bytes;
            this.list = list;
        }

        boolean isList() {
            return list != null;
        }

        BigInteger uint() {
            if (isList()) {
                throw new IllegalArgumentException("expected bytes, got list");
            }
            return new BigInteger(1, bytes);
        }

        String hex() {
            if (isList()) {
                throw new IllegalArgumentException("expected bytes, got list");
            }
            return "0x" + Keccak.hex(bytes, bytes.length);
        }
    }

    /** Decodes exactly one item spanning the whole input. Throws on malformed input. */
    static Item decode(byte[] data) {
        int[] cursor = {0};
        Item item = read(data, cursor, data.length);
        if (cursor[0] != data.length) {
            throw new IllegalArgumentException("trailing bytes after RLP item");
        }
        return item;
    }

    private static Item read(byte[] d, int[] cursor, int end) {
        int pos = cursor[0];
        if (pos >= end) {
            throw new IllegalArgumentException("truncated");
        }
        int prefix = d[pos] & 0xff;
        if (prefix < 0x80) {
            cursor[0] = pos + 1;
            return new Item(new byte[]{d[pos]}, null);
        }
        boolean isList = prefix >= 0xc0;
        int base = isList ? 0xc0 : 0x80;
        int length;
        int start;
        if (prefix <= base + 55) {
            length = prefix - base;
            start = pos + 1;
        } else {
            int lengthOfLength = prefix - base - 55;
            if (lengthOfLength > 4 || pos + 1 + lengthOfLength > end) {
                throw new IllegalArgumentException("bad length prefix");
            }
            length = 0;
            for (int i = 0; i < lengthOfLength; i++) {
                length = (length << 8) | (d[pos + 1 + i] & 0xff);
            }
            if (length < 0 || length < 56) {
                throw new IllegalArgumentException("non-canonical length");
            }
            start = pos + 1 + lengthOfLength;
        }
        if (start + length > end) {
            throw new IllegalArgumentException("item exceeds input");
        }
        if (!isList) {
            cursor[0] = start + length;
            return new Item(Arrays.copyOfRange(d, start, start + length), null);
        }
        List<Item> items = new ArrayList<>();
        cursor[0] = start;
        while (cursor[0] < start + length) {
            items.add(read(d, cursor, start + length));
        }
        return new Item(null, items);
    }

    static final class Described {
        final List<String> lines;
        final String label;

        Described(List<String> lines, String label) {
            this.lines = lines;
            this.label = label;
        }
    }

    /** Field-by-field description of a signed transaction. Never throws. */
    static Described describeTransaction(byte[] raw, Map<String, String> selectors) {
        List<String> lines = new ArrayList<>();
        if (raw.length == 0) {
            lines.add("raw:      empty");
            return new Described(lines, "(empty)");
        }
        int first = raw[0] & 0xff;
        String kind;
        String[] layout;
        byte[] payload;
        if (first >= 0xc0) {
            kind = "legacy";
            layout = LEGACY;
            payload = raw;
        } else {
            payload = Arrays.copyOfRange(raw, 1, raw.length);
            switch (first) {
                case 0x01 -> { kind = "EIP-2930 (type 1)"; layout = TYPE1; }
                case 0x02 -> { kind = "EIP-1559 (type 2)"; layout = TYPE2; }
                case 0x03 -> { kind = "EIP-4844 blob (type 3)"; layout = TYPE3; }
                case 0x04 -> { kind = "EIP-7702 set-code (type 4)"; layout = TYPE4; }
                default -> {
                    lines.add("raw:      " + raw.length + " bytes, unknown transaction type 0x" + Keccak.hex(raw, 1));
                    return new Described(lines, "unknown type");
                }
            }
        }
        lines.add("raw:      " + raw.length + " bytes, " + kind);

        try {
            Item tx = decode(payload);
            if (!tx.isList()) {
                throw new IllegalArgumentException("transaction is not an RLP list");
            }
            List<Item> fields = tx.list;
            if (first == 0x03 && fields.size() == 4 && fields.get(0).isList()) {
                // Network wrapper: [tx_payload_body, blobs, commitments, proofs].
                lines.add("blob sidecar: " + fields.get(1).list.size() + " blobs");
                fields = fields.get(0).list;
            }
            if (fields.size() != layout.length) {
                lines.add("(expected " + layout.length + " fields, found " + fields.size() + ")");
            }
            String label = renderFields(layout, fields, selectors, lines);
            return new Described(lines, label);
        } catch (RuntimeException e) {
            lines.add("(does not decode as " + kind + ": " + e.getMessage() + ")");
            return new Described(lines, kind + " (undecodable)");
        }
    }

    private static String renderFields(String[] layout, List<Item> fields, Map<String, String> selectors, List<String> lines) {
        String to = null;
        boolean creation = false;
        Item data = null;
        Item v = null;
        for (int i = 0; i < Math.min(layout.length, fields.size()); i++) {
            String name = layout[i];
            Item item = fields.get(i);
            String pad = " ".repeat(Math.max(1, 9 - name.length()));
            switch (name) {
                case "to" -> {
                    if (!item.isList() && item.bytes.length == 0) {
                        creation = true;
                        lines.add("to:       (contract creation)");
                    } else if (!item.isList() && item.bytes.length == 20) {
                        to = item.hex();
                        lines.add("to:       " + to);
                    } else {
                        lines.add("to:       " + describeOpaque(item) + "  (invalid address)");
                    }
                }
                case "value" -> lines.add("value:    " + item.uint() + "  " + Web3Summary.formatWei(item.uint().toString()));
                case "gasPrice", "maxPriorityFeePerGas", "maxFeePerGas", "maxFeePerBlobGas" ->
                        lines.add(name + ":" + pad + item.uint() + "  (" + gwei(item.uint()) + " gwei)");
                case "data" -> data = item;
                case "v" -> {
                    v = item;
                    BigInteger vv = item.uint();
                    String chain = vv.compareTo(BigInteger.valueOf(35)) >= 0
                            ? "  (EIP-155 chainId " + vv.subtract(BigInteger.valueOf(35)).shiftRight(1) + ")"
                            : "  (pre-EIP-155)";
                    lines.add("v:        " + vv + chain);
                }
                case "r", "s", "yParity" -> lines.add(name + ":" + pad + (name.equals("yParity") ? item.uint().toString() : item.hex()));
                case "accessList" -> renderAccessList(item, lines);
                case "blobVersionedHashes" -> renderHashList(item, lines);
                case "authorizationList" -> renderAuthorizationList(item, lines);
                default -> lines.add(name + ":" + pad + (item.isList() ? describeOpaque(item) : item.uint()));
            }
        }

        String call;
        if (data == null) {
            call = "(no data field)";
        } else if (data.isList()) {
            lines.add("data:     (unexpected list)");
            call = "(bad data)";
        } else if (creation) {
            lines.add("initcode: " + data.bytes.length + " bytes");
            call = "(contract creation)";
        } else {
            List<String> abi = Abi.describeCalldata("0x" + Keccak.hex(data.bytes, data.bytes.length), selectors);
            lines.addAll(abi);
            String label = Abi.callLabel(abi);
            call = label == null ? "(value transfer)" : label;
        }
        return call + (to == null ? "" : " → " + Web3Summary.shorten(to));
    }

    private static void renderAccessList(Item item, List<String> lines) {
        if (!item.isList()) {
            lines.add("accessList: (unexpected bytes)");
            return;
        }
        lines.add("accessList: " + item.list.size() + " entries");
        int shown = 0;
        for (Item entry : item.list) {
            if (shown++ >= MAX_LIST_PREVIEW) {
                lines.add("  ... " + (item.list.size() - MAX_LIST_PREVIEW) + " more");
                break;
            }
            if (entry.isList() && entry.list.size() == 2 && !entry.list.get(0).isList() && entry.list.get(1).isList()) {
                lines.add("  " + entry.list.get(0).hex() + "  " + entry.list.get(1).list.size() + " storage keys");
            } else {
                lines.add("  " + describeOpaque(entry));
            }
        }
    }

    private static void renderHashList(Item item, List<String> lines) {
        if (!item.isList()) {
            lines.add("blobVersionedHashes: (unexpected bytes)");
            return;
        }
        lines.add("blobVersionedHashes: " + item.list.size());
        for (int i = 0; i < Math.min(item.list.size(), MAX_LIST_PREVIEW); i++) {
            lines.add("  " + describeOpaque(item.list.get(i)));
        }
    }

    private static void renderAuthorizationList(Item item, List<String> lines) {
        if (!item.isList()) {
            lines.add("authorizationList: (unexpected bytes)");
            return;
        }
        lines.add("authorizationList: " + item.list.size() + " entries");
        for (int i = 0; i < Math.min(item.list.size(), MAX_LIST_PREVIEW); i++) {
            Item auth = item.list.get(i);
            // [chainId, address, nonce, yParity, r, s]
            if (auth.isList() && auth.list.size() == 6 && auth.list.stream().noneMatch(Item::isList)) {
                lines.add("  chainId=" + auth.list.get(0).uint() + " address=" + auth.list.get(1).hex()
                        + " nonce=" + auth.list.get(2).uint());
            } else {
                lines.add("  " + describeOpaque(auth));
            }
        }
    }

    private static String describeOpaque(Item item) {
        return item.isList() ? "[list of " + item.list.size() + "]" : item.hex();
    }

    private static String gwei(BigInteger wei) {
        return new BigDecimal(wei).divide(WEI_PER_GWEI).stripTrailingZeros().toPlainString();
    }
}
