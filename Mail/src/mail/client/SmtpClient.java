package mail.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * SMTP client (the sending UA / MTA client side). Works with our server and with real ones:
 *   new SmtpClient("smtp.gmail.com", 587, Tls.STARTTLS) → ehlo → starttls → ehlo → login → send
 */
public final class SmtpClient extends LineClient {

    public final String greeting;
    public final List<String> extensions = new ArrayList<>();

    public SmtpClient(String host, int port, Tls tls) throws IOException {
        super("SMTP", host, port, tls);
        greeting = expect(220);
        if (tls == Tls.STARTTLS) { ehlo("jumail-client"); starttls(); }
    }

    public void ehlo(String me) throws IOException {
        writeLine("EHLO " + me, null);
        extensions.clear();
        for (String l : expectMulti(250)) extensions.add(l.substring(4));
    }

    public void starttls() throws IOException {
        writeLine("STARTTLS", null);
        expect(220);
        wrapTls();
        ehlo("jumail-client");                   // capabilities must be fetched again after TLS
    }

    public void login(String user, String pass) throws IOException {
        if (extensions.stream().anyMatch(e -> e.toUpperCase().startsWith("AUTH") && e.toUpperCase().contains("PLAIN"))) {
            String tok = Base64.getEncoder().encodeToString(("\0" + user + "\0" + pass).getBytes(StandardCharsets.UTF_8));
            writeLine("AUTH PLAIN " + tok, "AUTH PLAIN " + secret(tok));
            expect(235);
        } else {
            writeLine("AUTH LOGIN", null);
            expect(334);
            String u = Base64.getEncoder().encodeToString(user.getBytes(StandardCharsets.UTF_8));
            writeLine(u, u);
            expect(334);
            String p = Base64.getEncoder().encodeToString(pass.getBytes(StandardCharsets.UTF_8));
            writeLine(p, secret(p));
            expect(235);
        }
    }

    /** MAIL FROM, RCPT TO (each), DATA with dot-stuffing. Returns the server's final reply. */
    public String send(String from, List<String> to, String rawMessage) throws IOException {
        writeLine("MAIL FROM:<" + from + ">", null);
        expect(250);
        int ok = 0;
        String lastErr = null;
        for (String r : to) {
            writeLine("RCPT TO:<" + r + ">", null);
            String l = readReply();
            if (l.startsWith("25")) ok++; else lastErr = l;
        }
        if (ok == 0) { writeLine("RSET", null); readReply(); throw new ProtocolException(lastErr == null ? "no recipients accepted" : lastErr); }
        writeLine("DATA", null);
        expect(354);
        StringBuilder b = new StringBuilder();
        for (String l : rawMessage.replace("\r\n", "\n").split("\n", -1)) b.append(l.startsWith(".") ? "." + l : l).append("\r\n");
        writeRaw(b.toString().getBytes(StandardCharsets.UTF_8), "(message: " + rawMessage.length() + " bytes, dot-stuffed)");
        writeLine(".", null);
        return expect(250);
    }

    public void quit() throws IOException { writeLine("QUIT", null); readReply(); close(); }

    // ------------------------------------------------------------------ replies

    private String readReply() throws IOException {
        String l;
        do { l = readLine(); } while (l.length() > 3 && l.charAt(3) == '-');
        return l;
    }

    private String expect(int code) throws IOException {
        String l = readReply();
        if (!l.startsWith(String.valueOf(code))) throw new ProtocolException(l);
        return l;
    }

    private List<String> expectMulti(int code) throws IOException {
        List<String> ls = new ArrayList<>();
        String l;
        do {
            l = readLine();
            if (!l.startsWith(String.valueOf(code))) throw new ProtocolException(l);
            ls.add(l);
        } while (l.length() > 3 && l.charAt(3) == '-');
        return ls;
    }
}
