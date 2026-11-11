package arp.security;

import arp.core.Hub;
import arp.core.Json;
import arp.model.MacAddress;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Enterprise Cisco Switchport Port-Security Simulator.
 *
 * Enforces hardware Layer 2 access control:
 * - Limits maximum MAC addresses per physical switch port (prevents CAM table exhaustion / macof)
 * - Sticky MAC address auto-learning
 * - Violation actions:
 *     - PROTECT: Drops unauthorized MAC frames silently
 *     - RESTRICT: Drops unauthorized MAC frames, increments counter, logs security alert
 *     - SHUTDOWN: Transitions port into ERR_DISABLE state, taking link completely offline
 */
public final class PortSecurity {

    public enum ViolationAction {
        PROTECT("Protect", "Silently drop frames from unauthorized MACs"),
        RESTRICT("Restrict", "Drop frames, log security alert, increment violation counter"),
        SHUTDOWN("Shutdown", "Transition port to ERR_DISABLE (port shut down)");

        private final String label;
        private final String desc;
        ViolationAction(String label, String desc) { this.label = label; this.desc = desc; }
        public String getLabel() { return label; }
        public String getDesc() { return desc; }
    }

    public static final class PortConfig {
        private final int port;
        private volatile boolean enabled = false;
        private volatile int maxMacs = 1;
        private volatile ViolationAction action = ViolationAction.RESTRICT;
        private volatile boolean sticky = true;
        private volatile boolean errDisabled = false;
        private final Set<MacAddress> secureMacs = Collections.synchronizedSet(new HashSet<>());
        private final AtomicInteger violations = new AtomicInteger();

        public PortConfig(int port) {
            this.port = port;
        }

        public int getPort() { return port; }
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getMaxMacs() { return maxMacs; }
        public void setMaxMacs(int maxMacs) { this.maxMacs = maxMacs; }
        public ViolationAction getAction() { return action; }
        public void setAction(ViolationAction action) { this.action = action; }
        public boolean isSticky() { return sticky; }
        public void setSticky(boolean sticky) { this.sticky = sticky; }
        public boolean isErrDisabled() { return errDisabled; }
        public void setErrDisabled(boolean errDisabled) { this.errDisabled = errDisabled; }
        public int getViolations() { return violations.get(); }
        public Set<MacAddress> getSecureMacs() { return new HashSet<>(secureMacs); }

        public void addSecureMac(MacAddress mac) {
            secureMacs.add(mac);
        }

        public void reset() {
            this.errDisabled = false;
        }

        public void clear() {
            this.errDisabled = false;
            this.violations.set(0);
            this.secureMacs.clear();
        }

        public String json() {
            List<String> macStrs = new ArrayList<>();
            for (MacAddress m : getSecureMacs()) macStrs.add(Json.str(m.toString()));
            return Json.obj(
                    "port", port,
                    "enabled", enabled,
                    "maxMacs", maxMacs,
                    "action", action.name(),
                    "actionLabel", action.getLabel(),
                    "sticky", sticky,
                    "errDisabled", errDisabled,
                    "violations", violations.get(),
                    "secureMacs", Json.arr(macStrs)
            );
        }
    }

    private final Map<Integer, PortConfig> portConfigs = new ConcurrentHashMap<>();

    public PortSecurity() {
    }

    public PortConfig getConfig(int port) {
        return portConfigs.computeIfAbsent(port, PortConfig::new);
    }

    public void enablePortSecurity(int port, int maxMacs, ViolationAction action) {
        PortConfig cfg = getConfig(port);
        cfg.setEnabled(true);
        cfg.setMaxMacs(maxMacs);
        cfg.setAction(action);
    }

    public void disablePortSecurity(int port) {
        PortConfig cfg = portConfigs.get(port);
        if (cfg != null) cfg.setEnabled(false);
    }

    public boolean isPortErrDisabled(int port) {
        PortConfig cfg = portConfigs.get(port);
        return cfg != null && cfg.isErrDisabled();
    }

    public void resetPort(int port) {
        PortConfig cfg = portConfigs.get(port);
        if (cfg != null) {
            cfg.reset();
            Hub.I.log(String.format("[PORT-SECURITY] Port %d recovered from ERR_DISABLE state.", port));
        }
    }

    /**
     * Inspects an incoming frame's source MAC address against port security rules.
     *
     * @param port Ingress port
     * @param srcMac Frame source MAC
     * @return true if permitted; false if dropped / violated
     */
    public boolean check(int port, MacAddress srcMac) {
        PortConfig cfg = portConfigs.get(port);
        if (cfg == null || !cfg.isEnabled()) {
            return true;
        }

        if (cfg.isErrDisabled()) {
            return false; // Port is shut down
        }

        if (srcMac.isBroadcast() || srcMac.isMulticast() || srcMac.isZero()) {
            return true;
        }

        if (cfg.secureMacs.contains(srcMac)) {
            return true; // Already authorized
        }

        if (cfg.secureMacs.size() < cfg.getMaxMacs()) {
            // Learn new sticky secure MAC
            cfg.addSecureMac(srcMac);
            Hub.I.log(String.format("[PORT-SECURITY] Port %d learned new secure MAC: %s (%d/%d)",
                    port, srcMac, cfg.secureMacs.size(), cfg.getMaxMacs()));
            return true;
        }

        // Limit exceeded -> Violation!
        int count = cfg.violations.incrementAndGet();
        Hub.I.log(String.format("[SECURITY ALERT] Port-Security VIOLATION on Port %d: Rogue MAC %s exceeded max %d allowed! Action=%s (Count=%d)",
                port, srcMac, cfg.getMaxMacs(), cfg.getAction().getLabel(), count));

        if (cfg.getAction() == ViolationAction.SHUTDOWN) {
            cfg.setErrDisabled(true);
            Hub.I.log(String.format("[PORT-SECURITY] Port %d transitioned to ERR_DISABLE (Link Down)!", port));
        }

        return false;
    }

    public List<PortConfig> getAllConfigs() {
        List<PortConfig> list = new ArrayList<>(portConfigs.values());
        Collections.sort(list, (a, b) -> Integer.compare(a.getPort(), b.getPort()));
        return list;
    }

    public String json() {
        List<String> configs = new ArrayList<>();
        for (PortConfig c : getAllConfigs()) {
            configs.add(c.json());
        }
        return Json.arr(configs);
    }
}
