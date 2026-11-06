package dhcp.lb;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Token-Bucket Rate Limiter to defend the DHCP Cluster against:
 * 1. Per-MAC rapid flooding
 * 2. Global DHCP Starvation Attacks (spoofed MAC floods attempting to exhaust the IP pool)
 */
public class RateLimiter {

    private static class Bucket {
        double tokens;
        long lastRefillMs;

        Bucket(double initialTokens) {
            this.tokens = initialTokens;
            this.lastRefillMs = System.currentTimeMillis();
        }
    }

    private final double maxTokensPerMac;
    private final double refillPerSecondPerMac;

    private final Bucket globalBucket;
    private final double maxGlobalTokens;
    private final double globalRefillPerSecond;

    private final ConcurrentHashMap<String, Bucket> macBuckets = new ConcurrentHashMap<>();
    private final AtomicLong totalAllowed = new AtomicLong(0);
    private final AtomicLong totalDropped = new AtomicLong(0);

    public RateLimiter(double maxTokensPerMac, double refillPerSecondPerMac, double maxGlobalTokens, double globalRefillPerSecond) {
        this.maxTokensPerMac = maxTokensPerMac;
        this.refillPerSecondPerMac = refillPerSecondPerMac;
        this.maxGlobalTokens = maxGlobalTokens;
        this.globalRefillPerSecond = globalRefillPerSecond;
        this.globalBucket = new Bucket(maxGlobalTokens);
    }

    public boolean allowRequest(String macAddress) {
        long now = System.currentTimeMillis();

        // 1. Check Global Token Bucket (protects against spoofed MAC DHCP Starvation floods)
        synchronized (globalBucket) {
            double elapsedSec = (now - globalBucket.lastRefillMs) / 1000.0;
            if (elapsedSec > 0) {
                globalBucket.tokens = Math.min(maxGlobalTokens, globalBucket.tokens + elapsedSec * globalRefillPerSecond);
                globalBucket.lastRefillMs = now;
            }
            if (globalBucket.tokens < 1.0) {
                totalDropped.incrementAndGet();
                return false;
            }
            globalBucket.tokens -= 1.0;
        }

        // 2. Check Per-MAC Token Bucket
        Bucket macBucket = macBuckets.computeIfAbsent(macAddress.toUpperCase(), k -> new Bucket(maxTokensPerMac));
        synchronized (macBucket) {
            double elapsedSec = (now - macBucket.lastRefillMs) / 1000.0;
            if (elapsedSec > 0) {
                macBucket.tokens = Math.min(maxTokensPerMac, macBucket.tokens + elapsedSec * refillPerSecondPerMac);
                macBucket.lastRefillMs = now;
            }
            if (macBucket.tokens < 1.0) {
                totalDropped.incrementAndGet();
                return false;
            }
            macBucket.tokens -= 1.0;
        }

        totalAllowed.incrementAndGet();
        return true;
    }

    public long getTotalAllowed() { return totalAllowed.get(); }
    public long getTotalDropped() { return totalDropped.get(); }
}
