package http.core;

import java.util.LinkedHashMap;
import java.util.Map;

/** HTTP status codes (RFC 9110 §15) with the reason phrase and what each one means in plain words. */
public final class Codes {
    private Codes() { }

    public static final Map<Integer, String[]> ALL = new LinkedHashMap<>();
    private static void c(int code, String reason, String meaning) { ALL.put(code, new String[] { reason, meaning }); }
    static {
        c(100, "Continue", "interim: the headers look fine, send the body now (answer to Expect: 100-continue)");
        c(200, "OK", "success: here is the resource");
        c(201, "Created", "the PUT/POST created a new resource (its URL is in Location)");
        c(204, "No Content", "success, and there is deliberately no body (DELETE, OPTIONS, replaced PUT)");
        c(206, "Partial Content", "here is only the byte range you asked for (Range: bytes=a-b)");
        c(301, "Moved Permanently", "the resource has a new URL for good: update your bookmark (Location)");
        c(302, "Found", "temporarily elsewhere: go to Location this time only");
        c(303, "See Other", "go GET the result at Location (used after a POST, e.g. after login)");
        c(304, "Not Modified", "your cached copy is still valid: no body sent (answer to a conditional GET)");
        c(400, "Bad Request", "the request is malformed (e.g. HTTP/1.1 without a Host header)");
        c(401, "Unauthorized", "you must authenticate first (see WWW-Authenticate)");
        c(403, "Forbidden", "authenticated or not, you may not have this");
        c(404, "Not Found", "no resource at this URL");
        c(405, "Method Not Allowed", "the resource exists, but not for this method (see Allow)");
        c(411, "Length Required", "a request body needs Content-Length or chunked coding");
        c(413, "Content Too Large", "the request body is larger than the server accepts");
        c(416, "Range Not Satisfiable", "the requested byte range lies outside the resource");
        c(500, "Internal Server Error", "the server failed while handling a valid request");
        c(501, "Not Implemented", "the server does not know this method at all");
        c(505, "HTTP Version Not Supported", "the request used a major HTTP version the server doesn't speak");
    }
    public static String reason(int code) { String[] r = ALL.get(code); return r == null ? "Unknown" : r[0]; }
    public static String meaning(int code) { String[] r = ALL.get(code); return r == null ? "" : r[1]; }
    public static String family(int code) {
        switch (code / 100) {
            case 1: return "1xx informational"; case 2: return "2xx success"; case 3: return "3xx redirection";
            case 4: return "4xx client error"; case 5: return "5xx server error"; default: return "?";
        }
    }
}
