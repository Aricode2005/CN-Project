package arp.core;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Standard Wireshark / libpcap 2.4 Binary PCAP File Generator.
 *
 * Allows exporting captured Ethernet and ARP simulation frames directly into
 * a standard .pcap binary format that can be opened in Wireshark.
 */
public final class PcapExporter {

    public static final int PCAP_MAGIC = 0xa1b2c3d4;
    public static final short PCAP_VERSION_MAJOR = 2;
    public static final short PCAP_VERSION_MINOR = 4;
    public static final int LINKTYPE_ETHERNET = 1;

    private PcapExporter() {}

    /**
     * Exports a list of captured frames into standard libpcap binary bytes.
     */
    public static byte[] exportToPcap(List<Hub.CapturedFrame> frames) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);

        // 1. Write 24-byte Global Header
        out.writeInt(PCAP_MAGIC);
        out.writeShort(PCAP_VERSION_MAJOR);
        out.writeShort(PCAP_VERSION_MINOR);
        out.writeInt(0); // thiszone (GMT to local correction)
        out.writeInt(0); // sigfigs (accuracy)
        out.writeInt(65535); // snaplen (max bytes per packet)
        out.writeInt(LINKTYPE_ETHERNET); // network link-layer type = 1 (Ethernet)

        // 2. Write Each Packet Record (16-byte Packet Header + Wire Bytes)
        if (frames != null) {
            for (Hub.CapturedFrame f : frames) {
                byte[] raw = f.rawBytes;
                if (raw == null || raw.length == 0) continue;

                long tsMs = f.timestampMs;
                int tsSec = (int) (tsMs / 1000);
                int tsUsec = (int) ((tsMs % 1000) * 1000);
                int wireLen = raw.length;

                out.writeInt(tsSec);
                out.writeInt(tsUsec);
                out.writeInt(wireLen); // incl_len
                out.writeInt(wireLen); // orig_len
                out.write(raw);
            }
        }

        out.flush();
        return baos.toByteArray();
    }
}
