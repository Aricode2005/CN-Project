package dhcp.client;

import dhcp.protocol.DhcpMessageType;
import dhcp.protocol.DhcpPacket;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Multi-Client DHCP Simulator for testing:
 * - Full RFC 2131 DORA (DISCOVER -> OFFER -> REQUEST -> ACK)
 * - Static VIP MAC requests
 * - DHCPRELEASE & DHCPDECLINE
 * - Concurrent Multi-Client Load Balancing distribution
 * - Simulated DHCP Starvation Attack (Rogue MAC flood)
 */
public class DhcpClientSimulator {

    private final int loadBalancerPort;
    private final Consumer<String> eventLogger;
    private final Random random = new Random();
    private final AtomicInteger clientSequence = new AtomicInteger(10);

    public DhcpClientSimulator(int loadBalancerPort, Consumer<String> eventLogger) {
        this.loadBalancerPort = loadBalancerPort;
        this.eventLogger = eventLogger;
    }

    /**
     * Executes a complete 4-way DORA handshake for a single simulated client over UDP.
     */
    public String runSingleClientDora(String macAddress, String hostname) {
        try (DatagramSocket clientSocket = new DatagramSocket()) {
            clientSocket.setSoTimeout(2500);
            int xid = random.nextInt(0x7FFFFFFF);
            InetAddress lbAddr = InetAddress.getByName("127.0.0.1");

            // Step 1: Send DHCPDISCOVER
            DhcpPacket discover = new DhcpPacket();
            discover.setOp(DhcpPacket.BOOTREQUEST);
            discover.setXid(xid);
            discover.setChaddr(macAddress);
            discover.setMessageType(DhcpMessageType.DHCPDISCOVER);
            discover.setOptionString(DhcpPacket.OPT_HOSTNAME, hostname);

            byte[] discBytes = discover.toBytes();
            clientSocket.send(new DatagramPacket(discBytes, discBytes.length, lbAddr, loadBalancerPort));
            log("[" + hostname + " | " + macAddress + "] Sent DHCPDISCOVER (xid=0x" + Integer.toHexString(xid) + ")");

            // Step 2: Receive DHCPOFFER
            byte[] buf = new byte[1500];
            DatagramPacket offerRaw = new DatagramPacket(buf, buf.length);
            clientSocket.receive(offerRaw);
            DhcpPacket offer = DhcpPacket.fromBytes(offerRaw.getData(), offerRaw.getLength());

            if (offer.getMessageType() != DhcpMessageType.DHCPOFFER) {
                log("[" + hostname + "] Unexpected response to DISCOVER: " + offer.getMessageType());
                return null;
            }

            String offeredIp = offer.getYiaddr();
            String serverId = offer.getOptionIp(DhcpPacket.OPT_SERVER_ID);
            log("[" + hostname + "] Received DHCPOFFER: IP=" + offeredIp + " from Server=" + serverId);

            // Step 3: Send DHCPREQUEST for the offered IP
            DhcpPacket request = new DhcpPacket();
            request.setOp(DhcpPacket.BOOTREQUEST);
            request.setXid(xid);
            request.setChaddr(macAddress);
            request.setMessageType(DhcpMessageType.DHCPREQUEST);
            request.setOptionIp(DhcpPacket.OPT_REQUESTED_IP, offeredIp);
            if (serverId != null) {
                request.setOptionIp(DhcpPacket.OPT_SERVER_ID, serverId);
            }
            request.setOptionString(DhcpPacket.OPT_HOSTNAME, hostname);

            byte[] reqBytes = request.toBytes();
            clientSocket.send(new DatagramPacket(reqBytes, reqBytes.length, lbAddr, loadBalancerPort));

            // Step 4: Receive DHCPACK or DHCPNAK
            DatagramPacket ackRaw = new DatagramPacket(buf, buf.length);
            clientSocket.receive(ackRaw);
            DhcpPacket ack = DhcpPacket.fromBytes(ackRaw.getData(), ackRaw.getLength());

            if (ack.getMessageType() == DhcpMessageType.DHCPACK) {
                String subnet = ack.getOptionIp(DhcpPacket.OPT_SUBNET_MASK);
                String router = ack.getOptionIp(DhcpPacket.OPT_ROUTER);
                String dns = ack.getOptionIp(DhcpPacket.OPT_DNS_SERVER);
                Integer leaseSec = ack.getOptionInt(DhcpPacket.OPT_LEASE_TIME);
                log(String.format("[%s] DORA COMPLETE (DHCPACK): Assigned IP=%s, Mask=%s, GW=%s, DNS=%s, Lease=%ds",
                        hostname, ack.getYiaddr(), subnet, router, dns, leaseSec));
                return ack.getYiaddr();
            } else {
                log("[" + hostname + "] Received DHCPNAK: " + ack.getOptionString(DhcpPacket.OPT_MESSAGE));
                return null;
            }
        } catch (Exception e) {
            log("[" + hostname + " | " + macAddress + "] DORA timed out or rate-limited (" + e.getMessage() + ")");
            return null;
        }
    }

    /**
     * Spawns N concurrent clients to demonstrate Load Balancing & Consistent Hashing across nodes.
     */
    public void simulateConcurrentClients(int count) {
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(count, 8));
        for (int i = 0; i < count; i++) {
            final int id = clientSequence.incrementAndGet();
            final String mac = String.format("AA:BB:CC:00:%02X:%02X", (id >> 8) & 0xFF, id & 0xFF);
            final String host = "workstation-" + id;
            pool.submit(() -> runSingleClientDora(mac, host));
        }
        pool.shutdown();
    }

    /**
     * Sends a DHCPRELEASE for a given MAC and IP.
     */
    public void sendRelease(String macAddress, String assignedIp) {
        try (DatagramSocket clientSocket = new DatagramSocket()) {
            DhcpPacket release = new DhcpPacket();
            release.setOp(DhcpPacket.BOOTREQUEST);
            release.setXid(random.nextInt(0x7FFFFFFF));
            release.setCiaddr(assignedIp);
            release.setChaddr(macAddress);
            release.setMessageType(DhcpMessageType.DHCPRELEASE);
            byte[] bytes = release.toBytes();
            clientSocket.send(new DatagramPacket(bytes, bytes.length, InetAddress.getByName("127.0.0.1"), loadBalancerPort));
            log("[CLIENT " + macAddress + "] Sent DHCPRELEASE for IP " + assignedIp);
        } catch (Exception e) {
            log("Failed to send DHCPRELEASE: " + e.getMessage());
        }
    }

    /**
     * Sends a DHCPINFORM from a client that already has an IP and wants local configuration options (DNS, Router, Domain).
     */
    public void sendInform(String macAddress, String clientIp, String hostname) {
        try (DatagramSocket clientSocket = new DatagramSocket()) {
            clientSocket.setSoTimeout(2000);
            DhcpPacket inform = new DhcpPacket();
            inform.setOp(DhcpPacket.BOOTREQUEST);
            inform.setXid(random.nextInt(0x7FFFFFFF));
            inform.setCiaddr(clientIp);
            inform.setChaddr(macAddress);
            inform.setMessageType(DhcpMessageType.DHCPINFORM);
            inform.setOptionString(DhcpPacket.OPT_HOSTNAME, hostname);
            byte[] bytes = inform.toBytes();
            clientSocket.send(new DatagramPacket(bytes, bytes.length, InetAddress.getByName("127.0.0.1"), loadBalancerPort));
            log("[" + hostname + " | " + macAddress + "] Sent DHCPINFORM (ciaddr=" + clientIp + ")");

            byte[] buf = new byte[1500];
            DatagramPacket ackRaw = new DatagramPacket(buf, buf.length);
            clientSocket.receive(ackRaw);
            DhcpPacket ack = DhcpPacket.fromBytes(ackRaw.getData(), ackRaw.getLength());
            if (ack.getMessageType() == DhcpMessageType.DHCPACK) {
                log(String.format("[%s] DHCPINFORM ACK: GW=%s, DNS=%s, Domain=%s",
                        hostname,
                        ack.getOptionIp(DhcpPacket.OPT_ROUTER),
                        ack.getOptionIp(DhcpPacket.OPT_DNS_SERVER),
                        ack.getOptionString(DhcpPacket.OPT_DOMAIN_NAME)));
            }
        } catch (Exception e) {
            log("[" + hostname + "] DHCPINFORM error: " + e.getMessage());
        }
    }

    /**
     * Sends a DHCPDECLINE indicating the offered IP was detected as already in use (ARP conflict).
     */
    public void sendDecline(String macAddress, String conflictedIp) {
        try (DatagramSocket clientSocket = new DatagramSocket()) {
            DhcpPacket decline = new DhcpPacket();
            decline.setOp(DhcpPacket.BOOTREQUEST);
            decline.setXid(random.nextInt(0x7FFFFFFF));
            decline.setChaddr(macAddress);
            decline.setMessageType(DhcpMessageType.DHCPDECLINE);
            decline.setOptionIp(DhcpPacket.OPT_REQUESTED_IP, conflictedIp);
            byte[] bytes = decline.toBytes();
            clientSocket.send(new DatagramPacket(bytes, bytes.length, InetAddress.getByName("127.0.0.1"), loadBalancerPort));
            log("[CLIENT " + macAddress + "] Sent DHCPDECLINE (ARP Conflict reported for IP " + conflictedIp + ")");
        } catch (Exception e) {
            log("Failed to send DHCPDECLINE: " + e.getMessage());
        }
    }

    /**
     * Simulates a Rogue Client launching a DHCP Starvation Flood to trigger Token-Bucket Rate Limiting.
     */
    public void simulateStarvationAttack(int packetBurstCount) {
        log("[SECURITY-SIM] Launching simulated DHCP Starvation flood (" + packetBurstCount + " rapid DISCOVER packets)...");
        try (DatagramSocket attackSocket = new DatagramSocket()) {
            InetAddress lbAddr = InetAddress.getByName("127.0.0.1");
            for (int i = 0; i < packetBurstCount; i++) {
                String spoofedMac = String.format("DE:AD:BE:EF:%02X:%02X", (i >> 8) & 0xFF, i & 0xFF);
                DhcpPacket pkt = new DhcpPacket();
                pkt.setOp(DhcpPacket.BOOTREQUEST);
                pkt.setXid(50000 + i);
                pkt.setChaddr(spoofedMac);
                pkt.setMessageType(DhcpMessageType.DHCPDISCOVER);
                pkt.setOptionString(DhcpPacket.OPT_HOSTNAME, "rogue-bot-" + i);
                byte[] bytes = pkt.toBytes();
                attackSocket.send(new DatagramPacket(bytes, bytes.length, lbAddr, loadBalancerPort));
            }
        } catch (Exception e) {
            log("[SECURITY-SIM] Error: " + e.getMessage());
        }
    }

    private void log(String msg) {
        if (eventLogger != null) {
            eventLogger.accept(msg);
        }
    }
}
