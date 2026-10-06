package com.cybersecurity.engine.intel;

import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.model.Severity;
import com.cybersecurity.engine.model.ThreatCategory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;

/**
 * Threat Intelligence Module.
 * Manages the IP reputation blacklist and calculates composite risk scores for security alerts.
 */
// Concept: Class
public class ThreatIntelEngine {
    private final Set<String> blacklistedIPs = new HashSet<>();

    // Concept: Constructor
    public ThreatIntelEngine() {
        loadBlacklist();
    }

    /**
     * Loads blacklisted IP addresses from resources.
     */
    private void loadBlacklist() {
        try (InputStream is = getClass().getResourceAsStream("/ip_blacklist.txt")) {
            if (is == null) {
                System.err.println("Warning: ip_blacklist.txt not found in resources. Operating with empty blacklist.");
                loadFallbackBlacklist();
                return;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                // Topic: Loops
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        blacklistedIPs.add(line);
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading IP blacklist: " + e.getMessage());
            loadFallbackBlacklist();
        }
    }

    private void loadFallbackBlacklist() {
        blacklistedIPs.add("185.220.101.5");
        blacklistedIPs.add("198.51.100.42");
        blacklistedIPs.add("203.0.113.113");
        blacklistedIPs.add("45.143.201.12");
        blacklistedIPs.add("85.25.43.10");
    }

    /**
     * Checks if an IP is in the blacklist.
     *
     * @param ip The IP address to check.
     * @return true if blacklisted, false otherwise.
     */
    // Concept: Methods
    public boolean isBlacklisted(String ip) {
        return blacklistedIPs.contains(ip);
    }

    /**
     * Adds an IP to the active blacklist database (dynamic blacklisting).
     *
     * @param ip The IP to blacklist.
     */
    // Concept: Methods
    public synchronized void addIPToBlacklist(String ip) {
        if (ip != null && !ip.isEmpty()) {
            blacklistedIPs.add(ip);
        }
    }

    public synchronized boolean removeIPFromBlacklist(String ip) {
        return blacklistedIPs.remove(ip);
    }

    public synchronized Set<String> getBlacklistedIPs() {
        return new HashSet<>(blacklistedIPs);
    }

    /**
     * Returns the size of the blacklist database.
     */
    public int getBlacklistSize() {
        return blacklistedIPs.size();
    }

    /**
     * Computes the compound risk score (0.0 to 10.0) based on log parameters and threat category.
     *
     * @param entry          The triggering LogEntry.
     * @param category       The detected ThreatCategory.
     * @param isBlacklisted  Whether the source IP is blacklisted.
     * @return A risk score between 0.0 and 10.0.
     */
    // Concept: Methods
    public double calculateRiskScore(LogEntry entry, ThreatCategory category, boolean isBlacklisted) {
        double score = 0.0;

        // 1. Base Score by Category
        score += switch (category) {
            case SQL_INJECTION -> 5.0;
            case XSS_ATTACK -> 4.0;
            case COMMAND_INJECTION -> 6.0;
            case DIRECTORY_TRAVERSAL -> 4.5;
            case MALICIOUS_URL -> 3.5;
            case BRUTE_FORCE -> 5.5;
            case SUSPICIOUS_IP -> 3.0;
            case TRAFFIC_ANOMALY -> 3.0;
            case SUSPICIOUS_BEHAVIOR -> 4.0;
        };

        // 2. IP Reputation multiplier / addition
        if (isBlacklisted) {
            score += 2.5;
        }

        // 3. User Risk Multiplier
        String user = entry.getUserInfo();
        if (user != null) {
            if ("root".equalsIgnoreCase(user) || "administrator".equalsIgnoreCase(user) || "SYSTEM".equalsIgnoreCase(user)) {
                score += 1.5;
            }
        }

        // 4. Status Code Risk Check
        if ("APACHE".equals(entry.getLogType()) && entry.getStatusCode() == 500) {
            score += 1.0; // Server error might indicate successful exploitation
        }

        // Cap score at 10.0
        return Math.min(10.0, score);
    }

    /**
     * Maps a composite risk score to a Severity level.
     *
     * @param riskScore Composite score (0.0 to 10.0).
     * @return Severity level enum.
     */
    public Severity mapRiskToSeverity(double riskScore) {
        if (riskScore >= 8.0) {
            return Severity.CRITICAL;
        } else if (riskScore >= 6.0) {
            return Severity.HIGH;
        } else if (riskScore >= 4.0) {
            return Severity.MEDIUM;
        } else {
            return Severity.LOW;
        }
    }
}
