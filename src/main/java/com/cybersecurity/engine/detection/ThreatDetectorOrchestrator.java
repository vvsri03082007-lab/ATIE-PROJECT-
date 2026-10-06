package com.cybersecurity.engine.detection;

import com.cybersecurity.engine.intel.ThreatIntelEngine;
import com.cybersecurity.engine.model.Alert;
import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.model.Severity;
import com.cybersecurity.engine.model.ThreatCategory;

import java.time.LocalDateTime;

/**
 * Orchestrator that executes all detection engines (Signature, Sliding Window, Z-Score, Threat Intel)
 * sequentially on parsed log entries.
 */
public class ThreatDetectorOrchestrator {
    private final SignatureDetector signatureDetector;
    private final SlidingWindowDetector slidingWindowDetector;
    private final ZScoreAnalyzer zScoreAnalyzer;
    private final ThreatIntelEngine threatIntelEngine;

    public ThreatDetectorOrchestrator() {
        this.signatureDetector = new SignatureDetector();
        this.slidingWindowDetector = new SlidingWindowDetector();
        this.zScoreAnalyzer = new ZScoreAnalyzer();
        this.threatIntelEngine = new ThreatIntelEngine();
    }

    public SignatureDetector getSignatureDetector() {
        return signatureDetector;
    }

    public SlidingWindowDetector getSlidingWindowDetector() {
        return slidingWindowDetector;
    }

    public ZScoreAnalyzer getzScoreAnalyzer() {
        return zScoreAnalyzer;
    }

    public ThreatIntelEngine getThreatIntelEngine() {
        return threatIntelEngine;
    }

    /**
     * Analyzes a single LogEntry and returns a generated Alert if a threat is identified.
     *
     * @param entry The parsed log entry.
     * @return An Alert object, or null if no threat is detected.
     */
    public Alert analyze(LogEntry entry) {
        if (entry == null) {
            return null;
        }

        ThreatCategory detectedCategory = null;
        String threatDescription = null;
        boolean isIpBlacklisted = threatIntelEngine.isBlacklisted(entry.getIpAddress());

        // 1. Sliding Window (Brute Force) Detection - High priority check
        SlidingWindowDetector.Result bruteForceResult = slidingWindowDetector.scan(entry);
        if (bruteForceResult != null) {
            detectedCategory = bruteForceResult.getCategory();
            threatDescription = bruteForceResult.getMessage();
        }

        // 2. Signature Detection (Trie & Boyer-Moore) - Checked if no brute force detected
        if (detectedCategory == null) {
            SignatureDetector.DetectionResult sigResult = signatureDetector.scan(entry);
            if (sigResult != null) {
                detectedCategory = sigResult.getCategory();
                threatDescription = sigResult.getReason();
            }
        }

        // 3. Traffic Anomaly (Z-Score) Detection - Evaluated in parallel
        if (detectedCategory == null) {
            ZScoreAnalyzer.AnomalyResult anomalyResult = zScoreAnalyzer.analyze(entry);
            if (anomalyResult != null) {
                detectedCategory = anomalyResult.getCategory();
                threatDescription = anomalyResult.getMessage();
            }
        }

        // 4. Blacklisted IP Access - Evaluated as default if no other threat is triggered
        if (detectedCategory == null && isIpBlacklisted) {
            detectedCategory = ThreatCategory.SUSPICIOUS_IP;
            threatDescription = String.format("Alert: Connection attempt from blacklisted IP address %s.", entry.getIpAddress());
        }

        // If a threat has been identified, construct the Alert
        if (detectedCategory != null) {
            double riskScore = threatIntelEngine.calculateRiskScore(entry, detectedCategory, isIpBlacklisted);
            Severity severity = threatIntelEngine.mapRiskToSeverity(riskScore);
            
            String affectedSystem = "LocalHost";
            if ("WINDOWS".equals(entry.getLogType())) {
                affectedSystem = "WIN-DC01"; // Default mockup host for Windows logs
            } else if ("SYSLOG".equals(entry.getLogType())) {
                affectedSystem = "Linux-Server-01";
            } else if ("APACHE".equals(entry.getLogType())) {
                affectedSystem = "Apache-Webserver";
            }

            // Create and return the alert
            Alert alert = new Alert(
                    LocalDateTime.now(),
                    detectedCategory,
                    severity,
                    entry.getIpAddress(),
                    affectedSystem,
                    threatDescription,
                    entry,
                    riskScore
            );

            // Dynamically add the offending IP to blacklist to prevent future hits
            // auto-blacklist on high-severity alert (HIGH or CRITICAL)
            if (!isIpBlacklisted && (severity == Severity.HIGH || severity == Severity.CRITICAL)) {
                threatIntelEngine.addIPToBlacklist(entry.getIpAddress());
            }

            return alert;
        }

        return null;
    }
}
