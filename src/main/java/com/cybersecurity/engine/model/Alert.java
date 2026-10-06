package com.cybersecurity.engine.model;

import java.time.LocalDateTime;

/**
 * Model class representing a detected security threat alert.
 * Implements Comparable to enable sorting inside the Priority Queue by Severity and Risk Score.
 */
// Concept: Class
public class Alert implements Comparable<Alert> {
    // Concept: Encapsulation
    private final LocalDateTime timestamp;
    private final ThreatCategory category;
    private final Severity severity;
    private final String sourceIp;
    private final String affectedSystem;
    private final String description;
    private final LogEntry triggeringLog;
    private final double riskScore;

    public Alert(LocalDateTime timestamp, ThreatCategory category, Severity severity,
                 String sourceIp, String affectedSystem, String description,
                 LogEntry triggeringLog, double riskScore) {
        this.timestamp = timestamp;
        this.category = category;
        this.severity = severity;
        this.sourceIp = sourceIp;
        this.affectedSystem = affectedSystem;
        this.description = description;
        this.triggeringLog = triggeringLog;
        this.riskScore = riskScore;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public ThreatCategory getCategory() {
        return category;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getAffectedSystem() {
        return affectedSystem;
    }

    public String getDescription() {
        return description;
    }

    public LogEntry getTriggeringLog() {
        return triggeringLog;
    }

    public double getRiskScore() {
        return riskScore;
    }

    /**
     * Maps the severity level enum to an integer weight for comparison.
     */
    public int getSeverityWeight() {
        return switch (severity) {
            case LOW -> 1;
            case MEDIUM -> 2;
            case HIGH -> 3;
            case CRITICAL -> 4;
        };
    }

    // Concept: Polymorphism (Comparable interface method overridden to implement custom sorting)
    @Override
    public int compareTo(Alert other) {
        // High severity levels sorted first (descending comparison)
        int sevCompare = Integer.compare(other.getSeverityWeight(), this.getSeverityWeight());
        if (sevCompare != 0) {
            return sevCompare;
        }
        // If severities are equal, compare risk scores (descending)
        return Double.compare(other.getRiskScore(), this.getRiskScore());
    }

    @Override
    public String toString() {
        return String.format("[%s] [%s] %s (Risk: %.1f) - Source IP: %s - %s",
                timestamp, severity, category.getDisplayName(), riskScore, sourceIp, description);
    }
}
