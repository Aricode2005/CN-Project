package route.core;

import java.util.Collection;
import java.util.Map;

/** Minimal JSON writer (no external libraries). */
public final class Json {
    private Json() { }

    public static String str(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder(s.length() + 8).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7e) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    /** Build an object from alternating key, value pairs. Values: String, Number, Boolean, null, or raw JSON via {@link Raw}. */
    public static String obj(Object... kv) {
        StringBuilder b = new StringBuilder("{");
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (i > 0) b.append(',');
            b.append(str(String.valueOf(kv[i]))).append(':').append(val(kv[i + 1]));
        }
        return b.append('}').toString();
    }

    public static String arr(Collection<String> rawItems) {
        StringBuilder b = new StringBuilder("[");
        boolean first = true;
        for (String s : rawItems) { if (!first) b.append(','); b.append(s); first = false; }
        return b.append(']').toString();
    }

    public static String val(Object v) {
        if (v == null) return "null";
        if (v instanceof Raw) return ((Raw) v).json;
        if (v instanceof Number || v instanceof Boolean) return String.valueOf(v);
        if (v instanceof Map) {
            StringBuilder b = new StringBuilder("{");
            boolean first = true;
            for (Object e : ((Map<?, ?>) v).entrySet()) {
                Map.Entry<?, ?> en = (Map.Entry<?, ?>) e;
                if (!first) b.append(',');
                b.append(str(String.valueOf(en.getKey()))).append(':').append(val(en.getValue()));
                first = false;
            }
            return b.append('}').toString();
        }
        return str(String.valueOf(v));
    }

    public static Raw raw(String json) { return new Raw(json); }

    public static final class Raw {
        final String json;
        Raw(String j) { this.json = j; }
    }
}
