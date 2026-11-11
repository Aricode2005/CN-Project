package dhcp.lb;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class RateLimiter {

    public enum Algorithm {
        TOKEN_BUCKET,
        SLIDING_WINDOW_COUNTER
    }

    private volatile Algorithm currentAlgorithm = Algorithm.TOKEN_BUCKET;

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

    private static class WindowCounter {
        long currentWindowStartMs;
        int previousCount;
        int currentCount;

        WindowCounter(long windowStartMs) {
            this.currentWindowStartMs = windowStartMs;
            this.previousCount = 0;
            this.currentCount = 0;
        }
    }

    private final long windowSizeMs = 1000L;
    private final WindowCounter globalWindowCounter = new WindowCounter(0L);
    private final ConcurrentHashMap<String, WindowCounter> macWindowCounters = new ConcurrentHashMap<>();

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
        if (currentAlgorithm == Algorithm.SLIDING_WINDOW_COUNTER) {
            return allowRequestSlidingWindow(macAddress);
        } else {
            return allowRequestTokenBucket(macAddress);
        }
    }

    private boolean allowRequestTokenBucket(String macAddress) {
        long now = System.currentTimeMillis();

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

    private boolean allowRequestSlidingWindow(String macAddress) {
        long now = System.currentTimeMillis();
        long currentWindowStart = now - (now % windowSizeMs);

        synchronized (globalWindowCounter) {
            if (currentWindowStart > globalWindowCounter.currentWindowStartMs) {
                long elapsedWindows = (currentWindowStart - globalWindowCounter.currentWindowStartMs) / windowSizeMs;
                globalWindowCounter.previousCount = (elapsedWindows == 1) ? globalWindowCounter.currentCount : 0;
                globalWindowCounter.currentCount = 0;
                globalWindowCounter.currentWindowStartMs = currentWindowStart;
            }
            double progress = (double) (now - globalWindowCounter.currentWindowStartMs) / windowSizeMs;
            double estimatedCount = (globalWindowCounter.previousCount * (1.0 - progress)) + globalWindowCounter.currentCount;
            if (estimatedCount >= maxGlobalTokens) {
                totalDropped.incrementAndGet();
                return false;
            }
            globalWindowCounter.currentCount++;
        }

        WindowCounter macCounter = macWindowCounters.computeIfAbsent(
                macAddress.toUpperCase(), k -> new WindowCounter(currentWindowStart));
        synchronized (macCounter) {
            if (currentWindowStart > macCounter.currentWindowStartMs) {
                long elapsedWindows = (currentWindowStart - macCounter.currentWindowStartMs) / windowSizeMs;
                macCounter.previousCount = (elapsedWindows == 1) ? macCounter.currentCount : 0;
                macCounter.currentCount = 0;
                macCounter.currentWindowStartMs = currentWindowStart;
            }
            double progress = (double) (now - macCounter.currentWindowStartMs) / windowSizeMs;
            double estimatedCount = (macCounter.previousCount * (1.0 - progress)) + macCounter.currentCount;
            if (estimatedCount >= maxTokensPerMac) {
                totalDropped.incrementAndGet();
                return false;
            }
            macCounter.currentCount++;
        }

        totalAllowed.incrementAndGet();
        return true;
    }

    public Algorithm getAlgorithm() { return currentAlgorithm; }
    public void setAlgorithm(Algorithm algorithm) { this.currentAlgorithm = algorithm; }
    public long getTotalAllowed() { return totalAllowed.get(); }
    public long getTotalDropped() { return totalDropped.get(); }
}
