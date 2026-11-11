package telnet.protocol;

import java.io.ByteArrayOutputStream;

/**
 * RFC 854 byte-stream codec.
 *
 * Decoding is a state machine, so a command split across two TCP segments
 * (e.g. "FF" at the end of one read and "FD 1F" at the start of the next) is still
 * recognised: TCP is a byte stream and has no message boundaries.
 *
 *   DATA --255--> IAC --251..254--> NEGOTIATE --opt--> DATA
 *                 IAC --250-------> SB_OPTION --opt--> SB_DATA --255--> SB_IAC --240--> DATA
 *                 IAC --255-------> DATA (escaped data byte 0xFF)
 *                 IAC --other-----> DATA (single command: AYT, IP, NOP ...)
 *
 * Encoding doubles every 0xFF in user data so it is not mistaken for IAC, and turns a bare
 * CR into CR NUL (the NVT end-of-line rules: CR LF = newline, CR NUL = carriage return).
 */
public final class TelnetCodec {

    public interface Listener {
        void onData(int b);
        void onCommand(int command);
        void onNegotiation(int verb, int option);
        void onSubnegotiation(int option, byte[] payload);
    }

    private enum State { DATA, IAC, NEGOTIATE, SB_OPTION, SB_DATA, SB_IAC }

    private final Listener listener;
    private State state = State.DATA;
    private int verb;
    private int sbOption;
    private final ByteArrayOutputStream sb = new ByteArrayOutputStream();

    public TelnetCodec(Listener listener) {
        this.listener = listener;
    }

    public void feed(byte[] buf, int off, int len) {
        for (int i = 0; i < len; i++) feed(buf[off + i] & 0xFF);
    }

    public void feed(int b) {
        switch (state) {
            case DATA:
                if (b == Telnet.IAC) state = State.IAC;
                else listener.onData(b);
                break;
            case IAC:
                if (b == Telnet.IAC) { listener.onData(Telnet.IAC); state = State.DATA; }
                else if (b >= Telnet.WILL && b <= Telnet.DONT) { verb = b; state = State.NEGOTIATE; }
                else if (b == Telnet.SB) { state = State.SB_OPTION; }
                else { listener.onCommand(b); state = State.DATA; }
                break;
            case NEGOTIATE:
                listener.onNegotiation(verb, b);
                state = State.DATA;
                break;
            case SB_OPTION:
                sbOption = b;
                sb.reset();
                state = State.SB_DATA;
                break;
            case SB_DATA:
                if (b == Telnet.IAC) state = State.SB_IAC;
                else sb.write(b);
                break;
            case SB_IAC:
                if (b == Telnet.SE) { listener.onSubnegotiation(sbOption, sb.toByteArray()); state = State.DATA; }
                else if (b == Telnet.IAC) { sb.write(Telnet.IAC); state = State.SB_DATA; }
                else { state = State.DATA; } // malformed: drop the subnegotiation
                break;
            default:
                state = State.DATA;
        }
    }

    /** Escape user data for the wire: 0xFF -> FF FF, bare CR -> CR NUL. */
    public static byte[] encodeData(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + 8);
        for (int i = 0; i < data.length; i++) {
            int b = data[i] & 0xFF;
            out.write(b);
            if (b == Telnet.IAC) out.write(Telnet.IAC);
            if (b == '\r' && (i + 1 >= data.length || data[i + 1] != '\n')) out.write(0);
        }
        return out.toByteArray();
    }
}
