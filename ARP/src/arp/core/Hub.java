package arp.core;

import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.protocol.ArpPacket;
import arp.protocol.EthernetFrame;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Central Telemetry Hub for the ARP Simulation & Security Lab.
 * Collects wire captures, live packet inspection, security alerts, and logs for the dashboard.
 */
public final class Hub {

    public static final Hub I = new Hub();
    private Hub() { }

    public final long startedAt = System.currentTimeMillis();
    private final SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss.SSS");

    // ------------------------------------------------------------------ Logs
    private final Ring<String> logs = new Ring<>(400);
    private final List<Consumer<String>> logListeners = new CopyOnWriteArrayList<>();
    public volatile boolean quiet;

    public void log(String msg) {
        String line = fmt.format(new Date()) + " " + msg;
        logs.add(line);
        if (!quiet) System.out.println(line);
        for (Consumer<String> l : logListeners) l.accept(line);
    }

    public List<String> logs() { return logs.snapshot(); }
    public void onLog(Consumer<String> l) { logListeners.add(l); }

    // ------------------------------------------------------------------ Captured Wire Frames
    public static final class CapturedFrame {
        public long seq;
        public final long timestampMs;
        public final int port;
        public final String srcMac;
        public final String srcVendor;
        public final String dstMac;
        public final String dstVendor;
        public final String etherType;
        public final String summary;
        public final String hexDump;
        public final int length;
        public final boolean isArp;
        public final boolean isBroadcast;
        public final boolean blockedByDai;
        public final byte[] rawBytes;
        public final int vlanId;

        public CapturedFrame(
                int port,
                EthernetFrame frame,
                boolean blockedByDai) {
            this.timestampMs = System.currentTimeMillis();
            this.port = port;
            this.srcMac = frame.getSourceMac().toString();
            this.srcVendor = frame.getSourceMac().getVendor();
            this.dstMac = frame.getDestinationMac().toString();
            this.dstVendor = frame.getDestinationMac().getVendor();
            this.isArp = frame.isArp() || frame.isRarp();
            this.isBroadcast = frame.isBroadcast();
            this.blockedByDai = blockedByDai;
            this.rawBytes = frame.toBytes();
            this.length = this.rawBytes.length;
            this.hexDump = frame.toHexDump();
            this.vlanId = frame.getVlanId();

            String vlanPrefix = frame.isTagged() ? String.format("[VLAN %d] ", frame.getVlanId()) : "";
            this.etherType = frame.isArp() ? "ARP (0x0806)"
                    : frame.isRarp() ? "RARP (0x8035)"
                    : frame.isIpv4() ? "IPv4 (0x0800)"
                    : String.format("0x%04X", frame.getEtherType());

            if (frame.isArp() || frame.isRarp()) {
                String arpSummary;   // a final field may be assigned only once, so set it after the try/catch
                try {
                    ArpPacket arp = ArpPacket.fromBytes(frame.getPayload());
                    arpSummary = vlanPrefix + arp.toDetailedString();
                } catch (Exception e) {
                    arpSummary = vlanPrefix + "ARP/RARP: [Malformed Payload]";
                }
                this.summary = arpSummary;
            } else if (frame.isIpv4()) {
                this.summary = vlanPrefix + "[IPv4 / ICMP] Payload " + frame.getPayload().length + " bytes";
            } else {
                this.summary = vlanPrefix + "Frame Type: " + etherType;
            }
        }

        public String json() {
            return Json.obj(
                    "seq", seq,
                    "t", timestampMs,
                    "port", port,
                    "vlanId", vlanId,
                    "srcMac", srcMac,
                    "srcVendor", srcVendor,
                    "dstMac", dstMac,
                    "dstVendor", dstVendor,
                    "etherType", etherType,
                    "summary", summary,
                    "hex", hexDump,
                    "length", length,
                    "isArp", isArp,
                    "isBroadcast", isBroadcast,
                    "blockedByDai", blockedByDai
            );
        }
    }

    private final Ring<CapturedFrame> frames = new Ring<>(1500);
    private long frameSeq;

    public void captureFrame(int port, EthernetFrame frame, boolean blockedByDai) {
        CapturedFrame cf = new CapturedFrame(port, frame, blockedByDai);
        synchronized (frames) {
            cf.seq = ++frameSeq;
            frames.add(cf);
        }
    }

    public List<CapturedFrame> framesSince(long seq) {
        List<CapturedFrame> out = new ArrayList<>();
        for (CapturedFrame f : frames.snapshot()) {
            if (f.seq > seq) out.add(f);
        }
        return out;
    }

    public List<CapturedFrame> allFrames() {
        return frames.snapshot();
    }

    // ------------------------------------------------------------------ MITM Intercepted Data
    public static final class InterceptedData {
        public final long timestampMs;
        public final String victim;
        public final String intendedTarget;
        public final String payloadPreview;

        public InterceptedData(String victim, String intendedTarget, String payloadPreview) {
            this.timestampMs = System.currentTimeMillis();
            this.victim = victim;
            this.intendedTarget = intendedTarget;
            this.payloadPreview = payloadPreview;
        }

        public String json() {
            return Json.obj(
                    "t", timestampMs,
                    "victim", victim,
                    "target", intendedTarget,
                    "data", payloadPreview
            );
        }
    }

    public final Ring<InterceptedData> intercepted = new Ring<>(200);

    public void logIntercepted(String victim, String target, String payload) {
        intercepted.add(new InterceptedData(victim, target, payload));
    }
}
