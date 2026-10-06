package com.cybersecurity.engine.report;

import com.cybersecurity.engine.model.Alert;
import com.cybersecurity.engine.model.Severity;
import com.cybersecurity.engine.model.ThreatCategory;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Report generation engine.
 * Generates an executive incident summary and dynamic technical details from threat data.
 */
// Concept: Class
public class IncidentReportGenerator {

    /**
     * Generates a comprehensive Markdown security report from a list of alerts.
     *
     * @param alerts The list of triggered alerts.
     * @param outputPath The file path where the report should be saved.
     * @throws IOException If write fails.
     */
    // Concept: Methods
    public static void generateMarkdownReport(List<Alert> alerts, String outputPath) throws IOException {
        if (alerts == null || outputPath == null) {
            throw new IllegalArgumentException("Alerts list and output path cannot be null");
        }

        // Sort alerts by timestamp for the timeline
        List<Alert> timelineAlerts = new ArrayList<>(alerts);
        timelineAlerts.sort(Comparator.comparing(Alert::getTimestamp));

        // Sort alerts by risk score for priority list
        List<Alert> prioritizedAlerts = new ArrayList<>(alerts);
        prioritizedAlerts.sort((a, b) -> Double.compare(b.getRiskScore(), a.getRiskScore()));

        // Calculate statistics
        int totalAlerts = alerts.size();
        Map<Severity, Integer> severityCounts = new EnumMap<>(Severity.class);
        Map<ThreatCategory, Integer> categoryCounts = new EnumMap<>(ThreatCategory.class);
        Set<String> uniqueIps = new HashSet<>();
        Set<String> uniqueSystems = new HashSet<>();

        // Topic: Loops
        for (Alert a : alerts) {
            severityCounts.put(a.getSeverity(), severityCounts.getOrDefault(a.getSeverity(), 0) + 1);
            categoryCounts.put(a.getCategory(), categoryCounts.getOrDefault(a.getCategory(), 0) + 1);
            uniqueIps.add(a.getSourceIp());
            uniqueSystems.add(a.getAffectedSystem());
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            writer.write("# SECURITY INCIDENT INVESTIGATION REPORT\n\n");
            writer.write("## 1. Executive Summary\n");
            writer.write(String.format("- **Report Generated At:** %s\n", 
                    LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))));
            writer.write(String.format("- **Total Incidents Triggered:** %d\n", totalAlerts));
            writer.write(String.format("- **Unique Attacking Sources (IPs):** %d\n", uniqueIps.size()));
            writer.write(String.format("- **Affected Infrastructure Nodes:** %d\n\n", uniqueSystems.size()));

            writer.write("### Incident Distribution by Severity\n");
            writer.write("| Severity | Count | Percentage |\n");
            writer.write("|---|---|---|\n");
            // Topic: Loops
            for (Severity sev : Severity.values()) {
                int count = severityCounts.getOrDefault(sev, 0);
                double pct = totalAlerts > 0 ? ((double) count / totalAlerts) * 100 : 0.0;
                writer.write(String.format("| **%s** | %d | %.1f%% |\n", sev, count, pct));
            }
            writer.write("\n");

            writer.write("### Incident Classification Breakdown\n");
            writer.write("| Threat Classification | Counts |\n");
            writer.write("|---|---|\n");
            // Topic: Loops
            for (ThreatCategory cat : ThreatCategory.values()) {
                int count = categoryCounts.getOrDefault(cat, 0);
                if (count > 0) {
                    writer.write(String.format("| %s | %d |\n", cat.getDisplayName(), count));
                }
            }
            writer.write("\n");

            writer.write("## 2. Attack Vector Analysis (Top Risk Items)\n");
            writer.write("| Risk Score | Severity | Classification | Source IP | Target Host | Description |\n");
            writer.write("|---|---|---|---|---|---|\n");
            int limit = Math.min(10, prioritizedAlerts.size());
            // Topic: Loops
            for (int i = 0; i < limit; i++) {
                Alert a = prioritizedAlerts.get(i);
                writer.write(String.format("| `%.1f/10.0` | **%s** | %s | `%s` | `%s` | %s |\n",
                        a.getRiskScore(), a.getSeverity(), a.getCategory().getDisplayName(), 
                        a.getSourceIp(), a.getAffectedSystem(), a.getDescription()));
            }
            writer.write("\n");

            writer.write("## 3. Incident Timeline (Chronological Audit)\n");
            writer.write("| Timestamp | Threat Category | Severity | Source IP | System Event Payload |\n");
            writer.write("|---|---|---|---|---|\n");
            // Topic: Loops
            for (Alert a : timelineAlerts) {
                String payloadExcerpt = a.getTriggeringLog().getPayload();
                if (payloadExcerpt != null && payloadExcerpt.length() > 60) {
                    payloadExcerpt = payloadExcerpt.substring(0, 57) + "...";
                }
                writer.write(String.format("| %s | %s | %s | `%s` | `%s` |\n",
                        a.getTriggeringLog().getTimestamp().format(DateTimeFormatter.ofPattern("HH:mm:ss")),
                        a.getCategory().getDisplayName(), a.getSeverity(), a.getSourceIp(), payloadExcerpt));
            }
            writer.write("\n");

            writer.write("## 4. Systems and Targets Impact Map\n");
            Map<String, List<Alert>> systemMap = new HashMap<>();
            // Topic: Loops
            for (Alert a : alerts) {
                systemMap.computeIfAbsent(a.getAffectedSystem(), k -> new ArrayList<>()).add(a);
            }
            // Topic: Loops
            for (Map.Entry<String, List<Alert>> entry : systemMap.entrySet()) {
                writer.write(String.format("### Node: `%s`\n", entry.getKey()));
                writer.write(String.format("- **Total Alerts Registered:** %d\n", entry.getValue().size()));
                Set<String> attackers = new HashSet<>();
                Set<ThreatCategory> categories = new HashSet<>();
                // Topic: Loops
                for (Alert a : entry.getValue()) {
                    attackers.add(a.getSourceIp());
                    categories.add(a.getCategory());
                }
                writer.write(String.format("- **Distinct Threat Vectors:** %s\n", categories.toString()));
                writer.write(String.format("- **Offending Source IPs:** %s\n\n", attackers.toString()));
            }

            // Topic: StringBuilder
            StringBuilder recommendationsBuilder = new StringBuilder();
            recommendationsBuilder.append("## 5. Security Mitigation Recommendations\n");
            recommendationsBuilder.append("Based on the identified alerts, the following immediate remediation actions are recommended:\n\n");

            Set<ThreatCategory> activeCategories = categoryCounts.keySet();
            if (activeCategories.contains(ThreatCategory.SQL_INJECTION)) {
                recommendationsBuilder.append("### SQL Injection Mitigation\n");
                recommendationsBuilder.append("- **Parameterized Queries:** Enforce SQL Prepared Statements across all dynamic database operations.\n");
                recommendationsBuilder.append("- **Input Sanitization:** Validate and escape all input queries using modern web security filters.\n");
                recommendationsBuilder.append("- **WAF Rule Deployment:** Update the Web Application Firewall to block common SQL queries containing `UNION` or `OR 1=1` patterns.\n\n");
            }
            if (activeCategories.contains(ThreatCategory.XSS_ATTACK)) {
                recommendationsBuilder.append("### Cross-Site Scripting (XSS) Mitigation\n");
                recommendationsBuilder.append("- **Output Escaping:** Apply strict context-sensitive output escaping (HTML, JS, CSS) on all user-submitted fields.\n");
                recommendationsBuilder.append("- **Content Security Policy (CSP):** Deploy a CSP header to prevent raw injection and inline script executions.\n\n");
            }
            if (activeCategories.contains(ThreatCategory.COMMAND_INJECTION)) {
                recommendationsBuilder.append("### Command Injection Mitigation\n");
                recommendationsBuilder.append("- **Disable Shell Execution:** Avoid spawning runtime shell processes (`cmd.exe`, `/bin/sh`) inside app logic.\n");
                recommendationsBuilder.append("- **Strict Whitelisting:** If system commands must be run, use hardcoded parameter vectors instead of direct string inputs.\n\n");
            }
            if (activeCategories.contains(ThreatCategory.DIRECTORY_TRAVERSAL)) {
                recommendationsBuilder.append("### Directory Traversal Mitigation\n");
                recommendationsBuilder.append("- **Canonical File Paths:** Enforce verification of canonical file paths (`getCanonicalPath()`) prior to file access.\n");
                recommendationsBuilder.append("- **Root Isolation (Chroot):** Restrict system access levels by running server daemons inside isolated directories.\n\n");
            }
            if (activeCategories.contains(ThreatCategory.BRUTE_FORCE)) {
                recommendationsBuilder.append("### Brute Force / Credential Stuffing Mitigation\n");
                recommendationsBuilder.append("- **Account Lockout Policy:** Enforce a lockout threshold (e.g. 5 failed login attempts in 60s locks account for 15m).\n");
                recommendationsBuilder.append("- **Rate Limiting:** Implement token bucket rate limiting on authentication routes.\n");
                recommendationsBuilder.append("- **Multi-Factor Authentication (MFA):** Mandate MFA across all privileged system administrative channels.\n\n");
            }
            if (activeCategories.contains(ThreatCategory.TRAFFIC_ANOMALY)) {
                recommendationsBuilder.append("### Traffic Volume Anomaly Mitigation\n");
                recommendationsBuilder.append("- **Intrusion Prevention Systems (IPS):** Configure automatic threshold filters to drop connection spikes from single sources.\n");
                recommendationsBuilder.append("- **Scale Infrastructure:** Setup automatic load balancer scaling queues to preserve availability.\n\n");
            }
            if (activeCategories.contains(ThreatCategory.SUSPICIOUS_IP) || activeCategories.contains(ThreatCategory.MALICIOUS_URL)) {
                recommendationsBuilder.append("### Threat Intelligence & Scanning Mitigation\n");
                recommendationsBuilder.append("- **Firewall Blocking:** Block the offending blacklisted IPs at the border routing gateway / firewall levels.\n");
                recommendationsBuilder.append("- **Decommission vulnerable services:** Disable outdated web endpoints (like administrative installer entrypoints).\n\n");
            }

            recommendationsBuilder.append("---\n");
            recommendationsBuilder.append("*Document generated automatically by Adaptive Cybersecurity Threat Intelligence Engine.*");

            writer.write(recommendationsBuilder.toString());
        }
    }
}
