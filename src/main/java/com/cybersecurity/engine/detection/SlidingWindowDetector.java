package com.cybersecurity.engine.detection;

import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.model.ThreatCategory;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Brute Force Detection Module using the Sliding Window Algorithm.
 * Tracks failed authentication attempts over a time window per IP and Username.
 */
public class SlidingWindowDetector {
    private final Map<String, Queue<LocalDateTime>> ipFailuresMap = new ConcurrentHashMap<>();
    private final Map<String, Queue<LocalDateTime>> userFailuresMap = new ConcurrentHashMap<>();

    private int timeWindowSeconds = 60;
    private int failureThreshold = 5;

    public SlidingWindowDetector() {}

    public SlidingWindowDetector(int timeWindowSeconds, int failureThreshold) {
        this.timeWindowSeconds = timeWindowSeconds;
        this.failureThreshold = failureThreshold;
    }

    public synchronized void setThresholds(int timeWindowSeconds, int failureThreshold) {
        this.timeWindowSeconds = timeWindowSeconds;
        this.failureThreshold = failureThreshold;
    }

    public int getTimeWindowSeconds() {
        return timeWindowSeconds;
    }

    public int getFailureThreshold() {
        return failureThreshold;
    }

    /**
     * Scans a log entry to check if it represents a failed authentication
     * and triggers brute force detection.
     *
     * @param entry The LogEntry to scan.
     * @return A Result object indicating if brute force was detected, or null.
     */
    public Result scan(LogEntry entry) {
        boolean isAuthFailure = false;

        // Determine if this log represents an authentication failure
        if ("APACHE".equals(entry.getLogType())) {
            // In Apache, POST /login.php with a 401 or redirect status, or specific pathways
            if ("POST".equalsIgnoreCase(entry.getRequestType()) && 
                (entry.getPayload().contains("login") || entry.getPayload().contains("auth"))) {
                if (entry.getStatusCode() == 401 || entry.getStatusCode() == 403) {
                    isAuthFailure = true;
                }
            }
        } else if ("SYSLOG".equals(entry.getLogType())) {
            if ("sshd".equals(entry.getRequestType()) && entry.getStatusCode() == 0) {
                isAuthFailure = true; // sshd failed password
            }
        } else if ("WINDOWS".equals(entry.getLogType())) {
            if ("4625".equals(entry.getRequestType())) {
                isAuthFailure = true; // Windows Event ID 4625: Logon Failure
            }
        }

        if (!isAuthFailure) {
            return null;
        }

        LocalDateTime timestamp = entry.getTimestamp();
        String ip = entry.getIpAddress();
        String user = entry.getUserInfo();

        // 1. Process IP sliding window
        boolean ipViolation = checkWindow(ip, timestamp, ipFailuresMap);

        // 2. Process Username sliding window (detects credential stuffing across multiple IPs)
        boolean userViolation = false;
        if (user != null && !user.isEmpty() && !"ANONYMOUS".equalsIgnoreCase(user) && !"SYSTEM".equalsIgnoreCase(user)) {
            userViolation = checkWindow(user, timestamp, userFailuresMap);
        }

        if (ipViolation) {
            return new Result(
                    ThreatCategory.BRUTE_FORCE,
                    String.format("Brute Force detected: IP %s exceeded %d authentication failures in %d seconds.",
                            ip, failureThreshold, timeWindowSeconds)
            );
        }

        if (userViolation) {
            return new Result(
                    ThreatCategory.BRUTE_FORCE,
                    String.format("Credential Stuffing / Password Guessing: Account '%s' exceeded %d authentication failures in %d seconds.",
                            user, failureThreshold, timeWindowSeconds)
            );
        }

        return null;
    }

    /**
     * Updates sliding window queue and checks threshold violation.
     */
    private boolean checkWindow(String key, LocalDateTime timestamp, Map<String, Queue<LocalDateTime>> map) {
        Queue<LocalDateTime> failures = map.computeIfAbsent(key, k -> new LinkedList<>());
        failures.add(timestamp);

        // Evict elements outside the sliding window
        while (!failures.isEmpty()) {
            LocalDateTime first = failures.peek();
            long diff = ChronoUnit.SECONDS.between(first, timestamp);
            if (diff > timeWindowSeconds) {
                failures.poll();
            } else {
                break;
            }
        }

        return failures.size() >= failureThreshold;
    }

    /**
     * Clear active trackers.
     */
    public void clear() {
        ipFailuresMap.clear();
        userFailuresMap.clear();
    }

    public static class Result {
        private final ThreatCategory category;
        private final String message;

        public Result(ThreatCategory category, String message) {
            this.category = category;
            this.message = message;
        }

        public ThreatCategory getCategory() {
            return category;
        }

        public String getMessage() {
            return message;
        }
    }
}
