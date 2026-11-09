import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Function selector lookup and ABI calldata decoding. Input is untrusted. */
final class Abi {
    private static final int MAX_RAW_WORDS = 64;
    private static final Map<String, String> BUILTIN = loadBuiltin();
    // ponytail: one-entry cache keyed on the raw settings string; fine for a single text field.
    private static volatile Map.Entry<String, Map<String, String>> cached;

    private Abi() {
    }

    /** selector (8 lowercase hex chars) -> canonical signature, builtin plus user extras. */
    static Map<String, String> table(String extraSignatures) {
        String key = extraSignatures == null ? "" : extraSignatures;
        Map.Entry<String, Map<String, String>> hit = cached;
        if (hit != null && hit.getKey().equals(key)) {
            return hit.getValue();
        }
        Map<String, String> table = new HashMap<>(BUILTIN);
        for (String signature : key.split("[\\s;]+")) {
            if (looksLikeSignature(signature)) {
                table.put(Keccak.selector(argsPart(signature)), signature);
            }
        }
        cached = Map.entry(key, Map.copyOf(table));
        return cached.getValue();
    }

    /** Human-readable lines for calldata hex ("0x..."). Never throws on bad input. */
    static List<String> describeCalldata(String hex, Map<String, String> table) {
        List<String> out = new ArrayList<>();
        byte[] data;
        try {
            data = fromHex(hex);
        } catch (RuntimeException e) {
            out.add("data: not valid hex");
            return out;
        }
        if (data.length == 0) {
            out.add("data: empty (plain value transfer or fallback)");
            return out;
        }
        if (data.length < 4) {
            out.add("data: " + data.length + " bytes, shorter than a selector");
            return out;
        }
        String selector = Keccak.hex(data, 4);
        String signature = table.get(selector);
        if (signature == null) {
            out.add("selector 0x" + selector + "  (unknown; add the signature under Settings > Wallety)");
            rawWords(data, out);
            return out;
        }
        String args = argsPart(signature);
        out.add("selector 0x" + selector + "  " + args);
        try {
            renderTuple(0, parseType(args.substring(args.indexOf('('))).components,
                    Arrays.copyOfRange(data, 4, data.length), "  ", out);
        } catch (RuntimeException e) {
            out.add("  (arguments do not decode as " + args + ")");
            rawWords(data, out);
        }
        return out;
    }

    /** Lines for an eth_call result given the request's signature (may be null or lack return types). */
    static List<String> describeReturn(String hex, String signature) {
        List<String> out = new ArrayList<>();
        byte[] data;
        try {
            data = fromHex(hex);
        } catch (RuntimeException e) {
            out.add("result: not valid hex");
            return out;
        }
        String returns = signature == null ? null : returnsPart(signature);
        if (data.length == 0) {
            out.add("result: empty  (reverted without reason, or no contract at `to`)");
            return out;
        }
        if (returns == null) {
            out.add("result: " + data.length + " bytes" + (signature == null
                    ? "  (unknown function; add its signature under Settings > Wallety)"
                    : "  (no return types for " + argsPart(signature) + "; add them as name(args)(types))"));
            rawWords(data, 0, out);
            return out;
        }
        out.add("returns " + returns);
        try {
            renderTuple(0, parseType(returns).components, data, "  ", out);
        } catch (RuntimeException e) {
            out.add("  (result does not decode as " + returns + ")");
            rawWords(data, 0, out);
        }
        return out;
    }

    /** "name(args)" of a signature that may carry "(returns)" after it. */
    static String argsPart(String signature) {
        int depth = 0;
        for (int i = signature.indexOf('('); i >= 0 && i < signature.length(); i++) {
            char c = signature.charAt(i);
            depth += c == '(' ? 1 : c == ')' ? -1 : 0;
            if (depth == 0) {
                return signature.substring(0, i + 1);
            }
        }
        return signature;
    }

    /** "(types)" after the argument list, or null when the signature has none. */
    static String returnsPart(String signature) {
        String rest = signature.substring(argsPart(signature).length());
        return rest.startsWith("(") && rest.endsWith(")") ? rest : null;
    }

    /** Short label for a describeCalldata result: function name, "0xselector" if unknown, null if no calldata. */
    static String callLabel(List<String> lines) {
        String head = lines.isEmpty() ? "" : lines.get(0);
        if (!head.startsWith("selector 0x")) {
            return null;
        }
        String rest = head.substring("selector 0x".length() + 8).strip();
        return rest.startsWith("(unknown") ? head.substring(9, 19) : rest.substring(0, rest.indexOf('('));
    }

    static boolean looksLikeSignature(String s) {
        int open = s.indexOf('(');
        return open > 0 && s.endsWith(")") && s.chars().allMatch(c -> c < 128 && !Character.isWhitespace(c));
    }

    static byte[] fromHex(String hex) {
        if (hex == null || !hex.startsWith("0x") || (hex.length() & 1) != 0) {
            throw new IllegalArgumentException("bad hex");
        }
        byte[] out = new byte[(hex.length() - 2) / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 + i * 2), 16);
            int lo = Character.digit(hex.charAt(3 + i * 2), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("bad hex");
            }
            out[i] = (byte) (hi << 4 | lo);
        }
        return out;
    }

    private static void rawWords(byte[] data, List<String> out) {
        rawWords(data, 4, out);
    }

    private static void rawWords(byte[] data, int from, List<String> out) {
        int words = (data.length - from + 31) / 32;
        for (int w = 0; w < Math.min(words, MAX_RAW_WORDS); w++) {
            int start = from + w * 32;
            byte[] word = Arrays.copyOfRange(data, start, Math.min(start + 32, data.length));
            out.add("  word[" + w + "] 0x" + Keccak.hex(word, word.length));
        }
        if (words > MAX_RAW_WORDS) {
            out.add("  ... " + (words - MAX_RAW_WORDS) + " more words");
        }
    }

    // --- type model -------------------------------------------------------

    static final class Type {
        final String name;            // "uint256", "address", "tuple", "array"
        final List<Type> components;  // tuple
        final Type elem;              // array
        final int length;             // array; -1 = dynamic

        Type(String name, List<Type> components, Type elem, int length) {
            this.name = name;
            this.components = components;
            this.elem = elem;
            this.length = length;
        }
    }

    static Type parseType(String s) {
        if (s.endsWith("]")) {
            int open = s.lastIndexOf('[');
            String len = s.substring(open + 1, s.length() - 1);
            int length = len.isEmpty() ? -1 : Integer.parseInt(len);
            if (length == 0 || length > 1 << 20) {
                throw new IllegalArgumentException("array length");
            }
            return new Type("array", null, parseType(s.substring(0, open)), length);
        }
        if (s.startsWith("(")) {
            if (!s.endsWith(")")) {
                throw new IllegalArgumentException("tuple");
            }
            List<Type> components = new ArrayList<>();
            String inner = s.substring(1, s.length() - 1);
            int depth = 0;
            int start = 0;
            for (int i = 0; i <= inner.length(); i++) {
                char c = i < inner.length() ? inner.charAt(i) : ',';
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                } else if (c == ',' && depth == 0) {
                    if (i > start) {
                        components.add(parseType(inner.substring(start, i)));
                    }
                    start = i + 1;
                }
            }
            return new Type("tuple", components, null, 0);
        }
        if (!s.matches("[a-z][a-z0-9]*")) {
            throw new IllegalArgumentException("type " + s);
        }
        return new Type(s, null, null, 0);
    }

    static boolean isDynamic(Type t) {
        return switch (t.name) {
            case "bytes", "string" -> true;
            case "array" -> t.length < 0 || isDynamic(t.elem);
            case "tuple" -> t.components.stream().anyMatch(Abi::isDynamic);
            default -> false;
        };
    }

    static int headSize(Type t) {
        if (isDynamic(t)) {
            return 32;
        }
        return switch (t.name) {
            case "array" -> t.length * headSize(t.elem);
            case "tuple" -> t.components.stream().mapToInt(Abi::headSize).sum();
            default -> 32;
        };
    }

    // base: start of the enclosing tuple's encoding (offsets are relative to it).
    // pos: where this value's head entry sits.
    private static void render(Type t, byte[] d, int base, int pos, String label, String indent, List<String> out) {
        if (isDynamic(t)) {
            int tail = base + wordInt(d, pos);
            switch (t.name) {
                case "bytes" -> {
                    int len = wordInt(d, tail);
                    byte[] bytes = slice(d, tail + 32, len);
                    out.add(indent + label + " bytes  0x" + Keccak.hex(bytes, bytes.length) + "  (" + len + " bytes)");
                }
                case "string" -> {
                    int len = wordInt(d, tail);
                    String text = new String(slice(d, tail + 32, len), StandardCharsets.UTF_8);
                    out.add(indent + label + " string  " + quote(text));
                }
                case "array" -> {
                    int len = t.length < 0 ? wordInt(d, tail) : t.length;
                    int elems = t.length < 0 ? tail + 32 : tail;
                    out.add(indent + label + " " + typeName(t) + "  [" + len + " items]");
                    if (len > d.length / 32 + 1) {
                        throw new IllegalArgumentException("array length exceeds data");
                    }
                    renderTuple(elems, nCopies(t.elem, len), d, indent + "  ", out);
                }
                case "tuple" -> {
                    out.add(indent + label + " tuple");
                    renderTuple(tail, t.components, d, indent + "  ", out);
                }
                default -> throw new IllegalStateException(t.name);
            }
            return;
        }
        switch (t.name) {
            case "array" -> {
                out.add(indent + label + " " + typeName(t) + "  [" + t.length + " items]");
                renderTuple(pos, nCopies(t.elem, t.length), d, indent + "  ", out);
            }
            case "tuple" -> {
                out.add(indent + label + " tuple");
                renderTuple(pos, t.components, d, indent + "  ", out);
            }
            default -> out.add(indent + label + " " + t.name + "  " + staticValue(t.name, word(d, pos)));
        }
    }

    private static void renderTuple(int base, List<Type> components, byte[] d, String indent, List<String> out) {
        int pos = base;
        for (int i = 0; i < components.size(); i++) {
            render(components.get(i), d, base, pos, "[" + i + "]", indent, out);
            pos += headSize(components.get(i));
        }
    }

    private static String staticValue(String name, byte[] w) {
        if (name.equals("address")) {
            return "0x" + Keccak.hex(Arrays.copyOfRange(w, 12, 32), 20);
        }
        if (name.equals("bool")) {
            return w[31] == 0 ? "false" : "true";
        }
        if (name.startsWith("uint")) {
            return new BigInteger(1, w).toString();
        }
        if (name.startsWith("int")) {
            return new BigInteger(w).toString();
        }
        if (name.startsWith("bytes") && name.length() > 5) {
            int n = Integer.parseInt(name.substring(5));
            return "0x" + Keccak.hex(w, Math.min(n, 32));
        }
        // ponytail: fixed/ufixed/function shown raw; nobody uses them in calldata.
        return "0x" + Keccak.hex(w, 32);
    }

    private static String typeName(Type t) {
        return switch (t.name) {
            case "array" -> typeName(t.elem) + (t.length < 0 ? "[]" : "[" + t.length + "]");
            case "tuple" -> "tuple";
            default -> t.name;
        };
    }

    private static List<Type> nCopies(Type t, int n) {
        return java.util.Collections.nCopies(n, t);
    }

    private static byte[] word(byte[] d, int pos) {
        return slice(d, pos, 32);
    }

    private static int wordInt(byte[] d, int pos) {
        BigInteger v = new BigInteger(1, word(d, pos));
        if (v.bitLength() > 30) {
            throw new IllegalArgumentException("offset or length too large");
        }
        return v.intValue();
    }

    private static byte[] slice(byte[] d, int pos, int len) {
        if (pos < 0 || len < 0 || pos + len > d.length) {
            throw new IllegalArgumentException("out of range");
        }
        return Arrays.copyOfRange(d, pos, pos + len);
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                sb.append('\\').append(c);
            } else if (c < 0x20 || c == 0x7f) {
                sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            } else {
                sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    private static Map<String, String> loadBuiltin() {
        Map<String, String> table = new HashMap<>();
        try (InputStream in = Abi.class.getResourceAsStream("/selectors.txt")) {
            if (in == null) {
                return table;
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.strip();
                if (looksLikeSignature(line)) {
                    table.put(Keccak.selector(argsPart(line)), line);
                }
            }
        } catch (java.io.IOException ignored) {
            // Bundled resource; a read failure just means fewer known selectors.
        }
        return table;
    }
}
