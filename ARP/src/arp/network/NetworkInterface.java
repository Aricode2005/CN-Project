package arp.network;

import arp.model.IpAddress;
import arp.model.MacAddress;
import arp.protocol.EthernetFrame;

import java.util.function.Consumer;

/**
 * Logical Network Interface Card (NIC) connecting a node to an L2 Switch port.
 */
public final class NetworkInterface {

    private final String name;
    private final MacAddress mac;
    private volatile IpAddress ip;
    private final IpAddress netmask;
    private final IpAddress gateway;

    private volatile EthernetSwitch connectedSwitch;
    private volatile int connectedPort;
    private volatile Consumer<EthernetFrame> frameReceiver;

    public NetworkInterface(String name, MacAddress mac, IpAddress ip, IpAddress netmask, IpAddress gateway) {
        this.name = name;
        this.mac = mac;
        this.ip = ip;
        this.netmask = netmask != null ? netmask : IpAddress.parse("255.255.255.0");
        this.gateway = gateway != null ? gateway : IpAddress.parse("192.168.1.1");
    }

    public void attach(EthernetSwitch sw, int port) {
        this.connectedSwitch = sw;
        this.connectedPort = port;
    }

    public void setFrameReceiver(Consumer<EthernetFrame> receiver) {
        this.frameReceiver = receiver;
    }

    public void send(EthernetFrame frame) {
        if (connectedSwitch != null) {
            connectedSwitch.handleIncomingFrame(connectedPort, frame);
        }
    }

    public void receive(EthernetFrame frame) {
        if (frameReceiver != null) {
            frameReceiver.accept(frame);
        }
    }

    public String getName() { return name; }
    public MacAddress getMac() { return mac; }
    public IpAddress getIp() { return ip; }
    public void setIp(IpAddress ip) { this.ip = ip; }
    public IpAddress getNetmask() { return netmask; }
    public IpAddress getGateway() { return gateway; }
    public int getConnectedPort() { return connectedPort; }
}
