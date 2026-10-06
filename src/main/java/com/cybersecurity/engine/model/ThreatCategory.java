package com.cybersecurity.engine.model;

/**
 * Enumeration representing different classifications of cybersecurity threats.
 */
public enum ThreatCategory {
    SQL_INJECTION("SQL Injection"),
    XSS_ATTACK("Cross-Site Scripting (XSS)"),
    COMMAND_INJECTION("Command Injection"),
    DIRECTORY_TRAVERSAL("Directory Traversal"),
    MALICIOUS_URL("Malicious URL Scan"),
    BRUTE_FORCE("Brute Force Attack"),
    SUSPICIOUS_IP("Blacklisted IP Access"),
    TRAFFIC_ANOMALY("Traffic Volume Anomaly"),
    SUSPICIOUS_BEHAVIOR("Suspicious Behavior Pattern");

    private final String displayName;

    ThreatCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
