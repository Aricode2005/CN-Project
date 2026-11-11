package arp.security;

import arp.core.Hub;
import arp.core.Json;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Enterprise Dynamic ARP Inspection (DAI) Rate Limiter.
 *
 * Implements Cisco "ip arp inspection limit rate <pps>" DoS prevention:
 * - Monitors ARP request / reply frame arrival rate per physical switch port.
 * - Prevents ARP Storms and CPU exhaustion.
 * - If an untrusted port exceeds rate threshold, excessive packets are dropped
 *   and port can optionally transition to ERR_DISABLE state.
 */
public final class ArpRateLimiter {

    public static final class PortRateTracker {
        private final int port;
        private volatile int rateLimitPps = 15; // default 15 packets per second
        private volatile boolean autoErrDisable = true;
        private volatile boolean rateErrDisabled = false;
        private final AtomicInteger currentSecondCount = new AtomicInteger();
        private volatile long currentSecondWindow = System.currentTimeMillis() / 1000;
        private final AtomicInteger rateViolations = new AtomicInteger();

        public PortRateTracker(int port) {
            this.port = port;
        }

        public int getPort() { return port; }
        public int getRateLimitPps() { return rateLimitPps; }
        public void setRateLimitPps(int pps) { this.rateLimitPps = pps; }
        public boolean isAutoErrDisable() { return autoErrDisable; }
        public void setAutoErrDisable(boolean autoErrDisable) { this.autoErrDisable = autoErrDisable; }
        public boolean isRateErrDisabled() { return rateErrDisabled; }
        public int getRateViolations() { return rateViolations.get(); }

        public void reset() {
            this.rateErrDisabled = false;
            this.currentSecondCount.set(0);
        }

        public synchronized boolean checkPacket() {
            if (rateErrDisabled) {
                return false;
            }
            if (rateLimitPps <= 0) {
                return true; // unlimited
            }

            long nowSec = System.currentTimeMillis() / 1000;
            if (nowSec != currentSecondWindow) {
                currentSecondWindow = nowSec;
                currentSecondCount.set(0);
            }

            int count = currentSecondCount.incrementAndGet();
            if (count > rateLimitPps) {
                int totalViolations = rateViolations.incrementAndGet();
                if (autoErrDisable) {
                    this.rateErrDisabled = true;
                    Hub.I.log(String.format("[DAI RATE LIMIT] Port %d EXCEEDED %d pps threshold (rate=%d)! Port transitioned to ERR_DISABLE!",
                            port, rateLimitPps, count));
                } else {
                    Hub.I.log(String.format("[DAI RATE LIMIT] Port %d dropped burst ARP frame (rate=%d pps > limit=%d)",
                            port, count, rateLimitPps));
                }
                return false;
            }
            return true;
        }

        public String json() {
            return Json.obj(
                    "port", port,
                    "rateLimitPps", rateLimitPps,
                    "rateErrDisabled", rateErrDisabled,
                    "violations", rateViolations.get()
            );
        }
    }

    private final Map<Integer, PortRateTracker> trackers = new ConcurrentHashMap<>();

    public ArpRateLimiter() {
    }

    public PortRateTracker getTracker(int port) {
        return trackers.computeIfAbsent(port, PortRateTracker::new);
    }

    public boolean check(int port) {
        PortRateTracker t = trackers.get(port);
        if (t == null) return true;
        return t.checkPacket();
    }

    public boolean isPortErrDisabled(int port) {
        PortRateTracker t = trackers.get(port);
        return t != null && t.isRateErrDisabled();
    }

    public void resetPort(int port) {
        PortRateTracker t = trackers.get(port);
        if (t != null) t.reset();
    }

    public List<PortRateTracker> getAllTrackers() {
        List<PortRateTracker> list = new ArrayList<>(trackers.values());
        Collections.sort(list, (a, b) -> Integer.compare(a.getPort(), b.getPort()));
        return list;
    }

    public String json() {
        List<String> list = new ArrayList<>();
        for (PortRateTracker t : getAllTrackers()) list.add(t.json());
        return Json.arr(list);
    }
}
