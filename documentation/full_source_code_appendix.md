# ACADEMIC PROJECT REPORT - APPENDIX: FULL SOURCE CODE

## Project: Adaptive Cybersecurity Threat Intelligence Engine (ATIE)
**A Real-Time, Multi-Format Security Information and Event Management (SIEM) Simulator**

---

### TABLE OF CONTENTS
1. [Module 1: Report Generation Engine](#1-module-1-report-generation-engine)
   - [IncidentReportGenerator.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/report/IncidentReportGenerator.java)
2. [Module 2: Core Data Models](#2-module-2-core-data-models)
   - [Severity.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/model/Severity.java)
   - [ThreatCategory.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/model/ThreatCategory.java)
   - [LogEntry.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/model/LogEntry.java)
   - [Alert.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/model/Alert.java)
3. [Module 3: Custom Algorithms & Data Structures](#3-module-3-custom-algorithms--data-structures)
   - [TrieNode.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/util/TrieNode.java)
   - [Trie.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/util/Trie.java)
   - [BoyerMooreMatcher.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/util/BoyerMooreMatcher.java)
4. [Module 4: Multi-Format Log Parsing Layer](#4-module-4-multi-format-log-parsing-layer)
   - [LogParser.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/LogParser.java)
   - [LogParserFactory.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/LogParserFactory.java)
   - [ApacheLogParser.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/ApacheLogParser.java)
   - [SyslogParser.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/SyslogParser.java)
   - [WindowsEventLogParser.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/WindowsEventLogParser.java)
5. [Module 5: Threat Detection & Anomaly Analysis Layer](#5-module-5-threat-detection--anomaly-analysis-layer)
   - [SignatureDetector.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/detection/SignatureDetector.java)
   - [SlidingWindowDetector.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/detection/SlidingWindowDetector.java)
   - [ZScoreAnalyzer.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/detection/ZScoreAnalyzer.java)
   - [ThreatDetectorOrchestrator.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/detection/ThreatDetectorOrchestrator.java)
6. [Module 6: Threat Intelligence & Risk Scoring Engine](#6-module-6-threat-intelligence--risk-scoring-engine)
   - [ThreatIntelEngine.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/intel/ThreatIntelEngine.java)
7. [Module 7: Alert Management & Priority Queue](#7-module-7-alert-management--priority-queue)
   - [AlertManager.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/alerting/AlertManager.java)
8. [Module 8: Background Log Replay Simulator](#8-module-8-background-log-replay-simulator)
   - [LogReplaySimulator.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/simulator/LogReplaySimulator.java)
9. [Module 9: Interactive CLI Dashboard Application Entrypoint](#9-module-9-interactive-cli-dashboard-application-entrypoint)
   - [Main.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/Main.java)
10. [Module 10: Web Dashboard Launcher](#10-module-10-web-dashboard-launcher)
    - [WebServerLauncher.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/web/WebServerLauncher.java)
11. [Module 11: Unit & Integration Verification Suite](#11-module-11-unit--integration-verification-suite)
    - [ThreatDetectorTest.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/test/java/com/cybersecurity/engine/ThreatDetectorTest.java)

---

## 1. Module 1: Report Generation Engine

### `IncidentReportGenerator.java`
**Package:** `com.cybersecurity.engine.report`  
**Description:** Consolidates active security telemetry, calculates metrics (severity distribution, threat classification, source IPs, affected infrastructure), performs chronological sorting, risk prioritization, and compiles mitigation strategies into Markdown format.

```java
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
public class IncidentReportGenerator {

    /**
     * Generates a comprehensive Markdown security report from a list of alerts.
     *
     * @param alerts The list of triggered alerts.
     * @param outputPath The file path where the report should be saved.
     * @throws IOException If write fails.
     */
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
            for (Severity sev : Severity.values()) {
                int count = severityCounts.getOrDefault(sev, 0);
                double pct = totalAlerts > 0 ? ((double) count / totalAlerts) * 100 : 0.0;
                writer.write(String.format("| **%s** | %d | %.1f%% |\n", sev, count, pct));
            }
            writer.write("\n");

            writer.write("### Incident Classification Breakdown\n");
            writer.write("| Threat Classification | Counts |\n");
            writer.write("|---|---|\n");
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
            for (Alert a : alerts) {
                systemMap.computeIfAbsent(a.getAffectedSystem(), k -> new ArrayList<>()).add(a);
            }
            for (Map.Entry<String, List<Alert>> entry : systemMap.entrySet()) {
                writer.write(String.format("### Node: `%s`\n", entry.getKey()));
                writer.write(String.format("- **Total Alerts Registered:** %d\n", entry.getValue().size()));
                Set<String> attackers = new HashSet<>();
                Set<ThreatCategory> categories = new HashSet<>();
                for (Alert a : entry.getValue()) {
                    attackers.add(a.getSourceIp());
                    categories.add(a.getCategory());
                }
                writer.write(String.format("- **Distinct Threat Vectors:** %s\n", categories.toString()));
                writer.write(String.format("- **Offending Source IPs:** %s\n\n", attackers.toString()));
            }

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
```

---

## 2. Module 2: Core Data Models

### `Severity.java`
**Package:** `com.cybersecurity.engine.model`  
```java
package com.cybersecurity.engine.model;

/**
 * Enumeration representing the severity levels of detected security alerts.
 */
public enum Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
```

### `ThreatCategory.java`
**Package:** `com.cybersecurity.engine.model`  
```java
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
```

### `LogEntry.java`
**Package:** `com.cybersecurity.engine.model`  
```java
package com.cybersecurity.engine.model;

import java.time.LocalDateTime;

/**
 * Model class representing a parsed log record.
 * Holds clean fields extracted from raw log strings.
 */
public class LogEntry {
    private final String rawLog;
    private final String logType; // "APACHE", "SYSLOG", "WINDOWS"
    private final LocalDateTime timestamp;
    private final String ipAddress;
    private final String requestType; // HTTP Method (e.g. GET/POST), Service Name (sshd), or EventID
    private final int statusCode; // HTTP Status Code, Syslog PID, or Windows Event Success/Failure Flag
    private final String userInfo; // Authenticating username or system user
    private final String payload; // URL path/query, syslog details, or Windows command line arguments

    public LogEntry(String rawLog, String logType, LocalDateTime timestamp, String ipAddress,
                    String requestType, int statusCode, String userInfo, String payload) {
        this.rawLog = rawLog;
        this.logType = logType;
        this.timestamp = timestamp;
        this.ipAddress = ipAddress;
        this.requestType = requestType;
        this.statusCode = statusCode;
        this.userInfo = userInfo;
        this.payload = payload;
    }

    public String getRawLog() {
        return rawLog;
    }

    public String getLogType() {
        return logType;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getRequestType() {
        return requestType;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getUserInfo() {
        return userInfo;
    }

    public String getPayload() {
        return payload;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s | IP: %s | User: %s | Req: %s | Code: %d | Payload: %s",
                logType, timestamp, ipAddress, userInfo, requestType, statusCode, payload);
    }
}
```

### `Alert.java`
**Package:** `com.cybersecurity.engine.model`  
```java
package com.cybersecurity.engine.model;

import java.time.LocalDateTime;

/**
 * Model class representing a detected security threat alert.
 * Implements Comparable to enable sorting inside the Priority Queue by Severity and Risk Score.
 */
public class Alert implements Comparable<Alert> {
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

    public int getSeverityWeight() {
        return switch (severity) {
            case LOW -> 1;
            case MEDIUM -> 2;
            case HIGH -> 3;
            case CRITICAL -> 4;
        };
    }

    @Override
    public int compareTo(Alert other) {
        int sevCompare = Integer.compare(other.getSeverityWeight(), this.getSeverityWeight());
        if (sevCompare != 0) {
            return sevCompare;
        }
        return Double.compare(other.getRiskScore(), this.getRiskScore());
    }

    @Override
    public String toString() {
        return String.format("[%s] [%s] %s (Risk: %.1f) - Source IP: %s - %s",
                timestamp, severity, category.getDisplayName(), riskScore, sourceIp, description);
    }
}
```

---

## 3. Module 3: Custom Algorithms & Data Structures

### `TrieNode.java`
**Package:** `com.cybersecurity.engine.util`  
```java
package com.cybersecurity.engine.util;

import com.cybersecurity.engine.model.ThreatCategory;
import java.util.HashMap;
import java.util.Map;

/**
 * Node structure for the custom Trie (Prefix Tree).
 * Used for prefix-based URL and directory path threat signature matching.
 */
public class TrieNode {
    final Map<Character, TrieNode> children = new HashMap<>();
    boolean isEndOfWord = false;
    ThreatCategory category = null;
}
```

### `Trie.java`
**Package:** `com.cybersecurity.engine.util`  
```java
package com.cybersecurity.engine.util;

import com.cybersecurity.engine.model.ThreatCategory;
import java.util.HashMap;
import java.util.Map;

/**
 * Custom Trie (Prefix Tree) data structure for efficient keyword and prefix signature matching.
 */
public class Trie {

    private final TrieNode root;

    public Trie() {
        this.root = new TrieNode();
    }

    public void insert(String pattern, ThreatCategory category) {
        if (pattern == null || pattern.isEmpty()) {
            return;
        }
        TrieNode current = root;
        for (char ch : pattern.toLowerCase().toCharArray()) {
            current = current.children.computeIfAbsent(ch, k -> new TrieNode());
        }
        current.isEndOfWord = true;
        current.category = category;
    }

    public ThreatCategory searchPrefixOf(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        TrieNode current = root;
        String lowerText = text.toLowerCase();
        for (int i = 0; i < lowerText.length(); i++) {
            char ch = lowerText.charAt(i);
            current = current.children.get(ch);
            if (current == null) {
                return null;
            }
            if (current.isEndOfWord) {
                return current.category;
            }
        }
        return null;
    }

    public ThreatCategory searchAnySubstringPrefix(String text) {
        if (text == null || text.isEmpty()) {
            return null;
        }
        String lowerText = text.toLowerCase();
        for (int i = 0; i < lowerText.length(); i++) {
            TrieNode current = root;
            for (int j = i; j < lowerText.length(); j++) {
                char ch = lowerText.charAt(j);
                current = current.children.get(ch);
                if (current == null) {
                    break;
                }
                if (current.isEndOfWord) {
                    return current.category;
                }
            }
        }
        return null;
    }
}
```

### `BoyerMooreMatcher.java`
**Package:** `com.cybersecurity.engine.util`  
```java
package com.cybersecurity.engine.util;

import java.util.HashMap;
import java.util.Map;

/**
 * Custom implementation of the Boyer-Moore String Matching algorithm.
 * Uses the Bad Character heuristic for efficient substring pattern matching.
 */
public class BoyerMooreMatcher {
    private final String pattern;
    private final Map<Character, Integer> badCharMap;

    public BoyerMooreMatcher(String pattern) {
        this.pattern = pattern.toLowerCase();
        this.badCharMap = new HashMap<>();
        preprocessBadCharacter();
    }

    private void preprocessBadCharacter() {
        int m = pattern.length();
        for (int i = 0; i < m; i++) {
            badCharMap.put(pattern.charAt(i), i);
        }
    }

    public int search(String text) {
        if (text == null || pattern == null) {
            return -1;
        }

        String lowerText = text.toLowerCase();
        int n = lowerText.length();
        int m = pattern.length();

        if (m == 0) {
            return 0;
        }
        if (n < m) {
            return -1;
        }

        int shift = 0;
        while (shift <= (n - m)) {
            int j = m - 1;

            while (j >= 0 && pattern.charAt(j) == lowerText.charAt(shift + j)) {
                j--;
            }

            if (j < 0) {
                return shift;
            } else {
                char mismatchedChar = lowerText.charAt(shift + j);
                int lastOccur = badCharMap.getOrDefault(mismatchedChar, -1);
                int badCharShift = j - lastOccur;
                shift += Math.max(1, badCharShift);
            }
        }
        return -1;
    }
}
```

---

## 4. Module 4: Multi-Format Log Parsing Layer

### `LogParser.java`
**Package:** `com.cybersecurity.engine.parser`  
```java
package com.cybersecurity.engine.parser;

import com.cybersecurity.engine.model.LogEntry;

/**
 * Interface defining the parsing contract for different log formats.
 */
public interface LogParser {
    LogEntry parse(String rawLogLine) throws Exception;
}
```

### `LogParserFactory.java`
**Package:** `com.cybersecurity.engine.parser`  
```java
package com.cybersecurity.engine.parser;

/**
 * Factory class for instantiation of LogParser implementations.
 * Follows the Factory Design Pattern.
 */
public class LogParserFactory {
    public static LogParser getParser(String logType) {
        if (logType == null) {
            throw new IllegalArgumentException("Log type cannot be null");
        }
        return switch (logType.toUpperCase()) {
            case "APACHE" -> new ApacheLogParser();
            case "SYSLOG" -> new SyslogParser();
            case "WINDOWS" -> new WindowsEventLogParser();
            default -> throw new IllegalArgumentException("Unsupported log type: " + logType);
        };
    }
}
```

### `ApacheLogParser.java`
**Package:** `com.cybersecurity.engine.parser`  
```java
package com.cybersecurity.engine.parser;

import com.cybersecurity.engine.model.LogEntry;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Log Parser for Apache Web Server logs (Combined and Common Log Formats).
 */
public class ApacheLogParser implements LogParser {
    private static final Pattern APACHE_PATTERN = Pattern.compile(
            "^(\\S+) (\\S+) (\\S+) \\[([^\\]]+)\\] \"([^\"]*)\" (\\d+) (\\S+)(?: \"([^\"]*)\" \"([^\"]*)\")?$"
    );

    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    @Override
    public LogEntry parse(String rawLogLine) throws Exception {
        if (rawLogLine == null || rawLogLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Log line is empty");
        }

        Matcher matcher = APACHE_PATTERN.matcher(rawLogLine.trim());
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Log line does not match Apache Combined format");
        }

        String ipAddress = matcher.group(1);
        String rfcIdentity = matcher.group(2);
        String userId = matcher.group(3);
        String timeStr = matcher.group(4);
        String requestStr = matcher.group(5);
        String statusStr = matcher.group(6);
        String bytesStr = matcher.group(7);

        LocalDateTime timestamp;
        try {
            ZonedDateTime zdt = ZonedDateTime.parse(timeStr, DATE_FORMATTER);
            timestamp = zdt.toLocalDateTime();
        } catch (Exception e) {
            timestamp = LocalDateTime.now();
        }

        String requestType = "UNKNOWN";
        String payload = requestStr;
        if (requestStr != null && !requestStr.isEmpty()) {
            String[] parts = requestStr.split("\\s+");
            if (parts.length > 0) {
                requestType = parts[0];
            }
            if (parts.length > 1) {
                payload = parts[1];
                try {
                    payload = java.net.URLDecoder.decode(payload.replace("+", " "), java.nio.charset.StandardCharsets.UTF_8);
                } catch (Exception ignored) {}
            }
        }

        int statusCode = 200;
        try {
            statusCode = Integer.parseInt(statusStr);
        } catch (NumberFormatException ignored) {}

        String userInfo = "-".equals(userId) ? "ANONYMOUS" : userId;

        return new LogEntry(
                rawLogLine,
                "APACHE",
                timestamp,
                ipAddress,
                requestType,
                statusCode,
                userInfo,
                payload
        );
    }
}
```

### `SyslogParser.java`
**Package:** `com.cybersecurity.engine.parser`  
```java
package com.cybersecurity.engine.parser;

import com.cybersecurity.engine.model.LogEntry;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Log Parser for Linux Syslog records (RFC 3164).
 */
public class SyslogParser implements LogParser {
    private static final Pattern SYSLOG_PATTERN = Pattern.compile(
            "^([A-Z][a-z]{2}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+([^:\\[\\s]+)(?:\\[(\\d+)\\])?:\\s+(.*)$"
    );

    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    );
    private static final Pattern USER_PATTERN = Pattern.compile(
            "(?:for|user|by)\\s+([a-zA-Z0-9_.-]+)"
    );

    @Override
    public LogEntry parse(String rawLogLine) throws Exception {
        if (rawLogLine == null || rawLogLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Log line is empty");
        }

        Matcher matcher = SYSLOG_PATTERN.matcher(rawLogLine.trim());
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Log line does not match Syslog format");
        }

        String timeStr = matcher.group(1);
        String hostname = matcher.group(2);
        String service = matcher.group(3);
        String pidStr = matcher.group(4);
        String message = matcher.group(5);

        String normalizedTime = timeStr.replaceAll("\\s+", " ");
        int currentYear = LocalDateTime.now().getYear();
        String fullTimeStr = currentYear + " " + normalizedTime;

        LocalDateTime timestamp;
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy MMM d HH:mm:ss", Locale.ENGLISH);
            timestamp = LocalDateTime.parse(fullTimeStr, formatter);
        } catch (Exception e) {
            timestamp = LocalDateTime.now();
        }

        String ipAddress = "127.0.0.1";
        Matcher ipMatcher = IP_PATTERN.matcher(message);
        if (ipMatcher.find()) {
            ipAddress = ipMatcher.group();
        }

        String userInfo = "SYSTEM";
        Matcher userMatcher = USER_PATTERN.matcher(message);
        if (userMatcher.find()) {
            userInfo = userMatcher.group(1);
            if ("invalid".equalsIgnoreCase(userInfo) && message.contains("invalid user")) {
                int index = message.indexOf("invalid user ");
                if (index != -1) {
                    String sub = message.substring(index + 13);
                    String[] parts = sub.split("\\s+");
                    if (parts.length > 0) {
                        userInfo = parts[0];
                    }
                }
            }
        } else if (message.contains("root")) {
            userInfo = "root";
        }

        int statusCode = 1;
        String lowerMessage = message.toLowerCase();
        if (lowerMessage.contains("fail") || lowerMessage.contains("error") || lowerMessage.contains("invalid")) {
            statusCode = 0;
        }

        return new LogEntry(
                rawLogLine,
                "SYSLOG",
                timestamp,
                ipAddress,
                service,
                statusCode,
                userInfo,
                message
        );
    }
}
```

### `WindowsEventLogParser.java`
**Package:** `com.cybersecurity.engine.parser`  
```java
package com.cybersecurity.engine.parser;

import com.cybersecurity.engine.model.LogEntry;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Log Parser for Windows Event Logs (formatted as CSV entries).
 * Parses Event ID, Source, Computer Name, User, and Event details.
 */
public class WindowsEventLogParser implements LogParser {

    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    );

    private static final Pattern ACCOUNT_NAME_PATTERN = Pattern.compile(
            "Account Name:\\s*([a-zA-Z0-9_.-]+)"
    );

    @Override
    public LogEntry parse(String rawLogLine) throws Exception {
        if (rawLogLine == null || rawLogLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Log line is empty");
        }

        String[] parts = rawLogLine.trim().split(",", 7);
        if (parts.length < 7) {
            throw new IllegalArgumentException("Log line does not match Windows Event CSV format");
        }

        String dateStr = parts[0];
        String timeStr = parts[1];
        String eventIdStr = parts[2];
        String source = parts[3];
        String defaultUser = parts[4];
        String computer = parts[5];
        String message = parts[6];

        LocalDateTime timestamp;
        try {
            timestamp = LocalDateTime.parse(dateStr + " " + timeStr, DATE_FORMATTER);
        } catch (Exception e) {
            timestamp = LocalDateTime.now();
        }

        int eventId = 0;
        try {
            eventId = Integer.parseInt(eventIdStr);
        } catch (NumberFormatException ignored) {}

        String ipAddress = "127.0.0.1";
        Matcher ipMatcher = IP_PATTERN.matcher(message);
        if (ipMatcher.find()) {
            ipAddress = ipMatcher.group();
        }

        String userInfo = defaultUser;
        Matcher accountMatcher = ACCOUNT_NAME_PATTERN.matcher(message);
        if (accountMatcher.find()) {
            String match = accountMatcher.group(1);
            if (!match.equalsIgnoreCase("SYSTEM")) {
                userInfo = match;
            }
        }

        int statusCode = (eventId == 4625) ? 0 : 1;

        return new LogEntry(
                rawLogLine,
                "WINDOWS",
                timestamp,
                ipAddress,
                eventIdStr,
                statusCode,
                userInfo,
                message
        );
    }
}
```

---

## 5. Module 5: Threat Detection & Anomaly Analysis Layer

### `SignatureDetector.java`
**Package:** `com.cybersecurity.engine.detection`  
```java
package com.cybersecurity.engine.detection;

import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.model.ThreatCategory;
import com.cybersecurity.engine.util.BoyerMooreMatcher;
import com.cybersecurity.engine.util.Trie;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Signature-Based Threat Detection Engine.
 * Utilizes a Trie for exact prefix matching and Boyer-Moore for substring matching.
 */
public class SignatureDetector {
    private final Trie pathTrie = new Trie();
    private final List<BoyerMooreMatchRule> bmVectors = new ArrayList<>();

    private static class BoyerMooreMatchRule {
        private final BoyerMooreMatcher matcher;
        private final ThreatCategory category;
        private final String rawPattern;

        public BoyerMooreMatchRule(String pattern, ThreatCategory category) {
            this.rawPattern = pattern;
            this.matcher = new BoyerMooreMatcher(pattern);
            this.category = category;
        }

        public boolean matches(String text) {
            return matcher.search(text) != -1;
        }

        public ThreatCategory getCategory() {
            return category;
        }

        public String getRawPattern() {
            return rawPattern;
        }
    }

    public SignatureDetector() {
        loadSignatures();
    }

    private void loadSignatures() {
        try (InputStream is = getClass().getResourceAsStream("/signatures.txt")) {
            if (is == null) {
                System.err.println("Warning: signatures.txt not found in resources. Utilizing default signature set.");
                loadFallbackSignatures();
                return;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) {
                        continue;
                    }
                    String[] parts = line.split("\\|", 2);
                    if (parts.length < 2) {
                        continue;
                    }
                    ThreatCategory category = ThreatCategory.valueOf(parts[0]);
                    String pattern = parts[1];

                    if (pattern.startsWith("/") || pattern.contains("..") || pattern.length() < 5) {
                        pathTrie.insert(pattern, category);
                    } else {
                        bmVectors.add(new BoyerMooreMatchRule(pattern, category));
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error loading signatures: " + e.getMessage());
            loadFallbackSignatures();
        }
    }

    private void loadFallbackSignatures() {
        pathTrie.insert("../", ThreatCategory.DIRECTORY_TRAVERSAL);
        pathTrie.insert("..\\", ThreatCategory.DIRECTORY_TRAVERSAL);
        pathTrie.insert("/etc/passwd", ThreatCategory.DIRECTORY_TRAVERSAL);
        pathTrie.insert("wp-admin", ThreatCategory.MALICIOUS_URL);
        
        bmVectors.add(new BoyerMooreMatchRule("UNION SELECT", ThreatCategory.SQL_INJECTION));
        bmVectors.add(new BoyerMooreMatchRule("' OR 1=1", ThreatCategory.SQL_INJECTION));
        bmVectors.add(new BoyerMooreMatchRule("<script>", ThreatCategory.XSS_ATTACK));
        bmVectors.add(new BoyerMooreMatchRule("cmd.exe", ThreatCategory.COMMAND_INJECTION));
        bmVectors.add(new BoyerMooreMatchRule("/bin/sh", ThreatCategory.COMMAND_INJECTION));
    }

    public DetectionResult scan(LogEntry entry) {
        String content = entry.getPayload();
        if (content == null || content.isEmpty()) {
            return null;
        }

        ThreatCategory trieCategory = pathTrie.searchAnySubstringPrefix(content);
        if (trieCategory != null) {
            return new DetectionResult(trieCategory, "Trie prefix signature matched in payload.");
        }

        for (BoyerMooreMatchRule rule : bmVectors) {
            if (rule.matches(content)) {
                return new DetectionResult(
                        rule.getCategory(),
                        "Boyer-Moore matched signature pattern: '" + rule.getRawPattern() + "'"
                );
            }
        }

        return null;
    }

    public static class DetectionResult {
        private final ThreatCategory category;
        private final String reason;

        public DetectionResult(ThreatCategory category, String reason) {
            this.category = category;
            this.reason = reason;
        }

        public ThreatCategory getCategory() {
            return category;
        }

        public String getReason() {
            return reason;
        }
    }
}
```

### `SlidingWindowDetector.java`
**Package:** `com.cybersecurity.engine.detection`  
```java
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

    public Result scan(LogEntry entry) {
        boolean isAuthFailure = false;

        if ("APACHE".equals(entry.getLogType())) {
            if ("POST".equalsIgnoreCase(entry.getRequestType()) && 
                (entry.getPayload().contains("login") || entry.getPayload().contains("auth"))) {
                if (entry.getStatusCode() == 401 || entry.getStatusCode() == 403) {
                    isAuthFailure = true;
                }
            }
        } else if ("SYSLOG".equals(entry.getLogType())) {
            if ("sshd".equals(entry.getRequestType()) && entry.getStatusCode() == 0) {
                isAuthFailure = true;
            }
        } else if ("WINDOWS".equals(entry.getLogType())) {
            if ("4625".equals(entry.getRequestType())) {
                isAuthFailure = true;
            }
        }

        if (!isAuthFailure) {
            return null;
        }

        LocalDateTime timestamp = entry.getTimestamp();
        String ip = entry.getIpAddress();
        String user = entry.getUserInfo();

        boolean ipViolation = checkWindow(ip, timestamp, ipFailuresMap);

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

    private boolean checkWindow(String key, LocalDateTime timestamp, Map<String, Queue<LocalDateTime>> map) {
        Queue<LocalDateTime> failures = map.computeIfAbsent(key, k -> new LinkedList<>());
        failures.add(timestamp);

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
```

### `ZScoreAnalyzer.java`
**Package:** `com.cybersecurity.engine.detection`  
```java
package com.cybersecurity.engine.detection;

import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.model.ThreatCategory;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Anomaly Detection Module using Z-Score Analysis.
 * Tracks log volume trends in time buckets and flags sudden traffic spikes or anomalies.
 */
public class ZScoreAnalyzer {
    private final List<Integer> baselineHistory = new ArrayList<>();
    private final int baselineLimit = 50;
    private double zScoreThreshold = 2.5;

    private LocalDateTime currentBucketStart = null;
    private int currentBucketCount = 0;
    private final int bucketDurationSeconds = 5;

    public ZScoreAnalyzer() {}

    public ZScoreAnalyzer(double zScoreThreshold) {
        this.zScoreThreshold = zScoreThreshold;
    }

    public synchronized void setZScoreThreshold(double threshold) {
        this.zScoreThreshold = threshold;
    }

    public double getZScoreThreshold() {
        return zScoreThreshold;
    }

    public List<Integer> getBaselineHistory() {
        return new ArrayList<>(baselineHistory);
    }

    public synchronized AnomalyResult analyze(LogEntry entry) {
        LocalDateTime logTime = entry.getTimestamp();

        if (currentBucketStart == null) {
            currentBucketStart = logTime;
            currentBucketCount = 1;
            return null;
        }

        long diff = ChronoUnit.SECONDS.between(currentBucketStart, logTime);

        if (diff < bucketDurationSeconds) {
            currentBucketCount++;
            return null;
        } else {
            int finishedCount = currentBucketCount;
            LocalDateTime finishedBucketStart = currentBucketStart;

            currentBucketStart = logTime;
            currentBucketCount = 1;

            AnomalyResult result = evaluateCount(finishedCount, finishedBucketStart);

            baselineHistory.add(finishedCount);
            if (baselineHistory.size() > baselineLimit) {
                baselineHistory.remove(0);
            }

            return result;
        }
    }

    private AnomalyResult evaluateCount(int count, LocalDateTime bucketTime) {
        if (baselineHistory.size() < 5) {
            return null;
        }

        double sum = 0;
        for (int c : baselineHistory) {
            sum += c;
        }
        double mean = sum / baselineHistory.size();

        double sqSum = 0;
        for (int c : baselineHistory) {
            sqSum += Math.pow(c - mean, 2);
        }
        double stdDev = Math.sqrt(sqSum / baselineHistory.size());

        if (stdDev < 0.0001) {
            if (count > mean + 5) {
                return new AnomalyResult(
                        ThreatCategory.TRAFFIC_ANOMALY,
                        String.format("Traffic Anomaly: Stable traffic (mean=%.1f, stddev=0) spiked to %d requests.", mean, count),
                        9.9
                );
            }
            return null;
        }

        double zScore = (count - mean) / stdDev;

        if (zScore > zScoreThreshold) {
            return new AnomalyResult(
                    ThreatCategory.TRAFFIC_ANOMALY,
                    String.format("Traffic Spike Detected: Count of %d exceeded mean of %.1f by %.2f standard deviations (Z-Score = %.2f).",
                            count, mean, zScore, zScore),
                    zScore
            );
        }

        return null;
    }

    public synchronized void reset() {
        baselineHistory.clear();
        currentBucketStart = null;
        currentBucketCount = 0;
    }

    public static class AnomalyResult {
        private final ThreatCategory category;
        private final String message;
        private final double zScore;

        public AnomalyResult(ThreatCategory category, String message, double zScore) {
            this.category = category;
            this.message = message;
            this.zScore = zScore;
        }

        public ThreatCategory getCategory() {
            return category;
        }

        public String getMessage() {
            return message;
        }

        public double getZScore() {
            return zScore;
        }
    }
}
```

### `ThreatDetectorOrchestrator.java`
**Package:** `com.cybersecurity.engine.detection`  
```java
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

    public Alert analyze(LogEntry entry) {
        if (entry == null) {
            return null;
        }

        ThreatCategory detectedCategory = null;
        String threatDescription = null;
        boolean isIpBlacklisted = threatIntelEngine.isBlacklisted(entry.getIpAddress());

        SlidingWindowDetector.Result bruteForceResult = slidingWindowDetector.scan(entry);
        if (bruteForceResult != null) {
            detectedCategory = bruteForceResult.getCategory();
            threatDescription = bruteForceResult.getMessage();
        }

        if (detectedCategory == null) {
            SignatureDetector.DetectionResult sigResult = signatureDetector.scan(entry);
            if (sigResult != null) {
                detectedCategory = sigResult.getCategory();
                threatDescription = sigResult.getReason();
            }
        }

        if (detectedCategory == null) {
            ZScoreAnalyzer.AnomalyResult anomalyResult = zScoreAnalyzer.analyze(entry);
            if (anomalyResult != null) {
                detectedCategory = anomalyResult.getCategory();
                threatDescription = anomalyResult.getMessage();
            }
        }

        if (detectedCategory == null && isIpBlacklisted) {
            detectedCategory = ThreatCategory.SUSPICIOUS_IP;
            threatDescription = String.format("Alert: Connection attempt from blacklisted IP address %s.", entry.getIpAddress());
        }

        if (detectedCategory != null) {
            double riskScore = threatIntelEngine.calculateRiskScore(entry, detectedCategory, isIpBlacklisted);
            Severity severity = threatIntelEngine.mapRiskToSeverity(riskScore);
            
            String affectedSystem = "LocalHost";
            if ("WINDOWS".equals(entry.getLogType())) {
                affectedSystem = "WIN-DC01";
            } else if ("SYSLOG".equals(entry.getLogType())) {
                affectedSystem = "Linux-Server-01";
            } else if ("APACHE".equals(entry.getLogType())) {
                affectedSystem = "Apache-Webserver";
            }

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

            if (!isIpBlacklisted && (severity == Severity.HIGH || severity == Severity.CRITICAL)) {
                threatIntelEngine.addIPToBlacklist(entry.getIpAddress());
            }

            return alert;
        }

        return null;
    }
}
```

---

## 6. Module 6: Threat Intelligence & Risk Scoring Engine

### `ThreatIntelEngine.java`
**Package:** `com.cybersecurity.engine.intel`  
```java
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
public class ThreatIntelEngine {
    private final Set<String> blacklistedIPs = new HashSet<>();

    public ThreatIntelEngine() {
        loadBlacklist();
    }

    private void loadBlacklist() {
        try (InputStream is = getClass().getResourceAsStream("/ip_blacklist.txt")) {
            if (is == null) {
                System.err.println("Warning: ip_blacklist.txt not found in resources. Operating with empty blacklist.");
                loadFallbackBlacklist();
                return;
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
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

    public boolean isBlacklisted(String ip) {
        return blacklistedIPs.contains(ip);
    }

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

    public int getBlacklistSize() {
        return blacklistedIPs.size();
    }

    public double calculateRiskScore(LogEntry entry, ThreatCategory category, boolean isBlacklisted) {
        double score = 0.0;

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

        if (isBlacklisted) {
            score += 2.5;
        }

        String user = entry.getUserInfo();
        if (user != null) {
            if ("root".equalsIgnoreCase(user) || "administrator".equalsIgnoreCase(user) || "SYSTEM".equalsIgnoreCase(user)) {
                score += 1.5;
            }
        }

        if ("APACHE".equals(entry.getLogType()) && entry.getStatusCode() == 500) {
            score += 1.0;
        }

        return Math.min(10.0, score);
    }

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
```

---

## 7. Module 7: Alert Management & Priority Queue

### `AlertManager.java`
**Package:** `com.cybersecurity.engine.alerting`  
```java
package com.cybersecurity.engine.alerting;

import com.cybersecurity.engine.model.Alert;
import com.cybersecurity.engine.model.Severity;
import com.cybersecurity.engine.model.ThreatCategory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;

/**
 * Thread-safe Alert Manager.
 * Utilizes a PriorityBlockingQueue to manage alerts, ensuring critical and high-risk alerts
 * are processed and displayed first.
 */
public class AlertManager {
    private final PriorityBlockingQueue<Alert> alertQueue = new PriorityBlockingQueue<>();
    private final List<Alert> alertHistory = new ArrayList<>();

    private final Map<ThreatCategory, Integer> categoryCounters = new ConcurrentHashMap<>();
    private final Map<Severity, Integer> severityCounters = new ConcurrentHashMap<>();

    public AlertManager() {
        clearCounters();
    }

    public synchronized void addAlert(Alert alert) {
        if (alert == null) {
            return;
        }
        alertQueue.add(alert);
        alertHistory.add(alert);

        categoryCounters.put(alert.getCategory(), categoryCounters.getOrDefault(alert.getCategory(), 0) + 1);
        severityCounters.put(alert.getSeverity(), severityCounters.getOrDefault(alert.getSeverity(), 0) + 1);
    }

    public Alert pollAlert() {
        return alertQueue.poll();
    }

    public synchronized List<Alert> getAlertHistory() {
        return new ArrayList<>(alertHistory);
    }

    public synchronized List<Alert> getPendingAlertsSorted() {
        List<Alert> sortedList = new ArrayList<>();
        PriorityBlockingQueue<Alert> tempQueue = new PriorityBlockingQueue<>(alertQueue);
        while (!tempQueue.isEmpty()) {
            sortedList.add(tempQueue.poll());
        }
        return sortedList;
    }

    public int getQueueSize() {
        return alertQueue.size();
    }

    public int getHistorySize() {
        return alertHistory.size();
    }

    public Map<ThreatCategory, Integer> getCategoryStats() {
        return new ConcurrentHashMap<>(categoryCounters);
    }

    public Map<Severity, Integer> getSeverityStats() {
        return new ConcurrentHashMap<>(severityCounters);
    }

    private void clearCounters() {
        for (ThreatCategory cat : ThreatCategory.values()) {
            categoryCounters.put(cat, 0);
        }
        for (Severity sev : Severity.values()) {
            severityCounters.put(sev, 0);
        }
    }

    public synchronized void clear() {
        alertQueue.clear();
        alertHistory.clear();
        clearCounters();
    }
}
```

---

## 8. Module 8: Background Log Replay Simulator

### `LogReplaySimulator.java`
**Package:** `com.cybersecurity.engine.simulator`  
```java
package com.cybersecurity.engine.simulator;

import com.cybersecurity.engine.alerting.AlertManager;
import com.cybersecurity.engine.detection.ThreatDetectorOrchestrator;
import com.cybersecurity.engine.model.Alert;
import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.parser.LogParser;
import com.cybersecurity.engine.parser.LogParserFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Real-Time Log Replay Simulator.
 * Runs in a background thread to replay security logs line-by-line and simulate live monitoring.
 * Follows the Observer Pattern to notify UI layers of parsed logs and triggered alerts.
 */
public class LogReplaySimulator {
    private final String logResourcePath;
    private final String logType;
    private final ThreatDetectorOrchestrator orchestrator;
    private final AlertManager alertManager;
    private final List<LogSimulationListener> listeners = new CopyOnWriteArrayList<>();

    private final AtomicBoolean running = new AtomicBoolean(false);
    private int delayMs = 250;
    private Thread simulationThread;

    public interface LogSimulationListener {
        void onLogParsed(LogEntry entry);
        void onAlertTriggered(Alert alert);
        void onSimulationComplete();
    }

    public LogReplaySimulator(String logResourcePath, String logType, 
                              ThreatDetectorOrchestrator orchestrator, AlertManager alertManager) {
        this.logResourcePath = logResourcePath;
        this.logType = logType;
        this.orchestrator = orchestrator;
        this.alertManager = alertManager;
    }

    public void addListener(LogSimulationListener listener) {
        listeners.add(listener);
    }

    public void removeListener(LogSimulationListener listener) {
        listeners.remove(listener);
    }

    public void setDelayMs(int delayMs) {
        this.delayMs = delayMs;
    }

    public int getDelayMs() {
        return delayMs;
    }

    public boolean isRunning() {
        return running.get();
    }

    public synchronized void start() {
        if (running.get()) {
            return;
        }
        running.set(true);

        simulationThread = new Thread(this::runReplay, "LogReplayThread");
        simulationThread.start();
    }

    public synchronized void stop() {
        if (!running.get()) {
            return;
        }
        running.set(false);
        if (simulationThread != null) {
            simulationThread.interrupt();
        }
    }

    private void runReplay() {
        LogParser parser = LogParserFactory.getParser(logType);
        
        try (InputStream is = getClass().getResourceAsStream(logResourcePath)) {
            if (is == null) {
                System.err.println("Simulator error: Resource " + logResourcePath + " not found.");
                running.set(false);
                notifySimulationComplete();
                return;
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                while (running.get() && (line = reader.readLine()) != null) {
                    if (line.trim().isEmpty() || line.startsWith("#")) {
                        continue;
                    }

                    try {
                        LogEntry entry = parser.parse(line);
                        notifyLogParsed(entry);

                        Alert alert = orchestrator.analyze(entry);
                        if (alert != null) {
                            alertManager.addAlert(alert);
                            notifyAlertTriggered(alert);
                        }

                    } catch (Exception e) {
                        // Continue on parsing error
                    }

                    try {
                        Thread.sleep(delayMs);
                    } catch (InterruptedException e) {
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Simulator error: " + e.getMessage());
        } finally {
            running.set(false);
            notifySimulationComplete();
        }
    }

    private void notifyLogParsed(LogEntry entry) {
        for (LogSimulationListener l : listeners) {
            l.onLogParsed(entry);
        }
    }

    private void notifyAlertTriggered(Alert alert) {
        for (LogSimulationListener l : listeners) {
            l.onAlertTriggered(alert);
        }
    }

    private void notifySimulationComplete() {
        for (LogSimulationListener l : listeners) {
            l.onSimulationComplete();
        }
    }
}
```

---

## 9. Module 9: Interactive CLI Dashboard Application Entrypoint

### `Main.java`
**Package:** `com.cybersecurity.engine`  
*(Key sections: banner, interactive command routing, reporting, threshold adjustment, live replay terminal).*

```java
package com.cybersecurity.engine;

import com.cybersecurity.engine.alerting.AlertManager;
import com.cybersecurity.engine.simulator.LogReplaySimulator;
import com.cybersecurity.engine.detection.ThreatDetectorOrchestrator;
import com.cybersecurity.engine.model.Alert;
import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.model.Severity;
import com.cybersecurity.engine.model.ThreatCategory;
import com.cybersecurity.engine.report.IncidentReportGenerator;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * Main application entrypoint.
 * Hosts the interactive ANSI terminal console dashboard, statistics visualizations,
 * and handles live log replay simulation.
 */
public class Main {
    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String BLUE = "\u001B[34m";
    private static final String PURPLE = "\u001B[35m";
    private static final String CYAN = "\u001B[36m";

    private final ThreatDetectorOrchestrator orchestrator = new ThreatDetectorOrchestrator();
    private final AlertManager alertManager = new AlertManager();
    private final Scanner scanner = new Scanner(System.in);

    private String selectedLogPath = "/sample_logs/apache.log";
    private String selectedLogType = "APACHE";
    private LogReplaySimulator currentSimulator = null;
    private int customDelayMs = 200;

    private com.cybersecurity.engine.web.WebServer webServer = null;

    public static void main(String[] args) {
        if (args.length > 0 && ("--web".equalsIgnoreCase(args[0]) || "--server".equalsIgnoreCase(args[0]))) {
            com.cybersecurity.engine.web.WebServerLauncher.main(args);
            return;
        }
        Main app = new Main();
        app.run();
    }

    private void run() {
        printBanner();

        boolean exit = false;
        while (!exit) {
            printMainMenu();
            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1" -> configureSimulation();
                case "2" -> runLiveSimulationMode();
                case "3" -> configureThresholds();
                case "4" -> manageThreatIntel();
                case "5" -> displayAlertDashboard();
                case "6" -> searchAlerts();
                case "7" -> clearAlerts();
                case "8" -> exportReport();
                case "9" -> {
                    stopActiveSimulation();
                    if (webServer != null) {
                        webServer.stop();
                    }
                    System.out.println(CYAN + "\nShutting down ATIE Engine. Goodbye!" + RESET);
                    exit = true;
                }
                case "10" -> launchWebDashboard();
                default -> System.out.println(RED + "Invalid choice! Please select 1-10." + RESET);
            }
        }
    }

    private void printBanner() {
        System.out.println(CYAN + BOLD);
        System.out.println("╔══════════════════════════════════════════════════════════════════════╗");
        System.out.println("║       ADAPTIVE CYBERSECURITY THREAT INTELLIGENCE ENGINE (ATIE)       ║");
        System.out.println("║          Real-Time Multi-Format SIEM & Log Intrusion Simulator       ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════╝" + RESET);
    }

    private void printMainMenu() {
        System.out.println("\n" + BOLD + "--- ATIE MAIN OPERATIONAL MENU ---" + RESET);
        System.out.printf("Current Config: [%s%s%s] File: %s | Delay: %dms\n",
                GREEN, selectedLogType, RESET, selectedLogPath, customDelayMs);
        System.out.println("1. Configure Simulation Log Source & Stream Speed");
        System.out.println("2. Start Live Simulation & Intrusion Monitor");
        System.out.println("3. Adjust Engine Detection Thresholds (Z-Score / Brute Force)");
        System.out.println("4. Threat Intelligence & IP Reputation Blacklist Manager");
        System.out.println("5. View Analytics Dashboard & Priority Alert Queue");
        System.out.println("6. Search & Filter Alerts by Keyword / IP");
        System.out.println("7. Clear Active Alerts and Telemetry Counters");
        System.out.println("8. Export Security Incident Investigation Report (Markdown)");
        System.out.println("9. Exit ATIE Console");
        System.out.println("10. Launch Web Operations Center (Browser UI)");
        System.out.print(BOLD + "\nEnter option (1-10): " + RESET);
    }

    private void exportReport() {
        System.out.println("\n" + BOLD + "--- EXPORT SECURITY INVESTIGATION REPORT ---" + RESET);
        List<Alert> alerts = alertManager.getAlertHistory();
        if (alerts.isEmpty()) {
            System.out.println(YELLOW + "Warning: No alerts logged to export. Run live simulation mode first." + RESET);
            return;
        }

        String reportFileName = "incident_report.md";
        System.out.print("Enter output filename (default: incident_report.md): ");
        String inputName = scanner.nextLine().trim();
        if (!inputName.isEmpty()) {
            reportFileName = inputName;
        }

        try {
            IncidentReportGenerator.generateMarkdownReport(alerts, reportFileName);
            System.out.println(GREEN + "Report exported successfully to: " + BOLD + reportFileName + RESET);
        } catch (IOException e) {
            System.out.println(RED + "Failed to write report file: " + e.getMessage() + RESET);
        }
    }
}
```

---

## 10. Module 10: Web Dashboard Launcher

### `WebServerLauncher.java`
**Package:** `com.cybersecurity.engine.web`  
```java
package com.cybersecurity.engine.web;

import java.awt.Desktop;
import java.net.URI;

/**
 * Standalone launcher for the ATIE Web Operations Center.
 */
public class WebServerLauncher {
    private static final String CYAN = "\u001B[36m";
    private static final String GREEN = "\u001B[32m";
    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";

    public static void main(String[] args) {
        int port = 8080;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (Exception ignored) {}
        }

        System.out.println(CYAN + BOLD);
        System.out.println("╔══════════════════════════════════════════════════════════════════════╗");
        System.out.println("║         ATIE CYBERSECURITY OPERATIONS CENTER (WEB SERVER)            ║");
        System.out.println("║             Next-Gen SIEM Live Telemetry & Detection Console         ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════╝" + RESET);

        try {
            WebServer webServer = new WebServer(port);
            webServer.start();

            String url = "http://localhost:" + port + "/";
            System.out.println("\n" + GREEN + BOLD + ">>> Dashboard live at: " + url + RESET);
            System.out.println(CYAN + "Press Ctrl+C in terminal to stop the web server." + RESET + "\n");

            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                try {
                    Desktop.getDesktop().browse(new URI(url));
                } catch (Exception ignored) {}
            }

            Thread.currentThread().join();

        } catch (Exception e) {
            System.err.println("Failed to start WebServer: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
```

---

## 11. Module 11: Unit & Integration Verification Suite

### `ThreatDetectorTest.java`
**Package:** `com.cybersecurity.engine`  
```java
package com.cybersecurity.engine;

import com.cybersecurity.engine.alerting.AlertManager;
import com.cybersecurity.engine.detection.SignatureDetector;
import com.cybersecurity.engine.detection.SlidingWindowDetector;
import com.cybersecurity.engine.intel.ThreatIntelEngine;
import com.cybersecurity.engine.detection.ZScoreAnalyzer;
import com.cybersecurity.engine.model.*;
import com.cybersecurity.engine.parser.*;
import com.cybersecurity.engine.util.BoyerMooreMatcher;
import com.cybersecurity.engine.util.Trie;

import org.junit.jupiter.api.Test;
import java.time.LocalDateTime;
import java.util.List;
import java.util.PriorityQueue;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for checking all modules in the Adaptive Cybersecurity Threat Intelligence Engine.
 */
public class ThreatDetectorTest {

    @Test
    public void testTrieSignatureMatching() {
        Trie trie = new Trie();
        trie.insert("/etc/passwd", ThreatCategory.DIRECTORY_TRAVERSAL);
        trie.insert("wp-admin", ThreatCategory.MALICIOUS_URL);

        assertEquals(ThreatCategory.DIRECTORY_TRAVERSAL, trie.searchPrefixOf("/etc/passwd/somefile"));
        assertNull(trie.searchPrefixOf("/etc/var"));

        assertEquals(ThreatCategory.MALICIOUS_URL, trie.searchAnySubstringPrefix("/site/wp-admin/install.php"));
        assertEquals(ThreatCategory.DIRECTORY_TRAVERSAL, trie.searchAnySubstringPrefix("/viewer.php?file=../../etc/passwd"));
        assertNull(trie.searchAnySubstringPrefix("/index.html"));
    }

    @Test
    public void testBoyerMooreMatcher() {
        BoyerMooreMatcher matcher = new BoyerMooreMatcher("UNION SELECT");

        assertTrue(matcher.search("GET /index.php?id=1 UNION SELECT * FROM users") >= 0);
        assertTrue(matcher.search("union select id from customers") >= 0);
        assertEquals(-1, matcher.search("GET /index.php?id=1"));
    }

    @Test
    public void testApacheLogParser() throws Exception {
        ApacheLogParser parser = new ApacheLogParser();
        String logLine = "127.0.0.1 - - [24/Jun/2026:18:00:01 +0530] \"GET /index.html HTTP/1.1\" 200 4526 \"http://localhost/\" \"Mozilla/5.0\"";
        
        LogEntry entry = parser.parse(logLine);
        
        assertEquals("127.0.0.1", entry.getIpAddress());
        assertEquals("GET", entry.getRequestType());
        assertEquals("/index.html", entry.getPayload());
        assertEquals(200, entry.getStatusCode());
        assertEquals("ANONYMOUS", entry.getUserInfo());
        assertEquals("APACHE", entry.getLogType());
    }

    @Test
    public void testSyslogParser() throws Exception {
        SyslogParser parser = new SyslogParser();
        String logLine = "Jun 24 18:05:02 server-01 sshd[12401]: Failed password for invalid user oracle from 192.168.1.15 port 54321 ssh2";
        
        LogEntry entry = parser.parse(logLine);
        
        assertEquals("192.168.1.15", entry.getIpAddress());
        assertEquals("sshd", entry.getRequestType());
        assertEquals("oracle", entry.getUserInfo());
        assertEquals(0, entry.getStatusCode());
        assertEquals("SYSLOG", entry.getLogType());
    }

    @Test
    public void testWindowsEventLogParser() throws Exception {
        WindowsEventLogParser parser = new WindowsEventLogParser();
        String logLine = "2026-06-24,18:10:10,4625,Microsoft-Windows-Security-Auditing,SYSTEM,WIN-DC01,An account failed to log on. Account Name: target_user, IP Address: 203.0.113.113";
        
        LogEntry entry = parser.parse(logLine);
        
        assertEquals("203.0.113.113", entry.getIpAddress());
        assertEquals("4625", entry.getRequestType());
        assertEquals("target_user", entry.getUserInfo());
        assertEquals(0, entry.getStatusCode());
        assertEquals("WINDOWS", entry.getLogType());
    }

    @Test
    public void testSlidingWindowBruteForce() {
        SlidingWindowDetector detector = new SlidingWindowDetector(60, 3);
        
        LocalDateTime now = LocalDateTime.now();
        LogEntry fail1 = new LogEntry("raw", "WINDOWS", now, "192.168.1.1", "4625", 0, "user1", "Failed");
        LogEntry fail2 = new LogEntry("raw", "WINDOWS", now.plusSeconds(5), "192.168.1.1", "4625", 0, "user1", "Failed");
        LogEntry fail3 = new LogEntry("raw", "WINDOWS", now.plusSeconds(10), "192.168.1.1", "4625", 0, "user1", "Failed");
        
        assertNull(detector.scan(fail1));
        assertNull(detector.scan(fail2));
        
        SlidingWindowDetector.Result result = detector.scan(fail3);
        assertNotNull(result);
        assertEquals(ThreatCategory.BRUTE_FORCE, result.getCategory());
        assertTrue(result.getMessage().contains("Brute Force detected"));
    }

    @Test
    public void testZScoreAnomalyDetection() {
        ZScoreAnalyzer analyzer = new ZScoreAnalyzer(2.0);
        
        LocalDateTime time = LocalDateTime.of(2026, 6, 24, 18, 0, 0);
        
        for (int b = 0; b < 6; b++) {
            LocalDateTime bucketStart = time.plusSeconds(b * 5);
            for (int i = 0; i < 10; i++) {
                analyzer.analyze(new LogEntry("raw", "APACHE", bucketStart.plusSeconds(1), "127.0.0.1", "GET", 200, "-", "path"));
            }
        }
        
        assertTrue(analyzer.getBaselineHistory().size() >= 5);
        
        LocalDateTime spikeTime = time.plusSeconds(30);
        for (int i = 0; i < 50; i++) {
            analyzer.analyze(new LogEntry("raw", "APACHE", spikeTime.plusSeconds(1), "127.0.0.1", "GET", 200, "-", "path"));
        }
        
        assertNotNull(analyzer.analyze(new LogEntry("raw", "APACHE", spikeTime.plusSeconds(6), "127.0.0.1", "GET", 200, "-", "path")));
    }

    @Test
    public void testAlertPriorityQueueSorting() {
        AlertManager manager = new AlertManager();
        
        LogEntry mockLog = new LogEntry("raw", "APACHE", LocalDateTime.now(), "127.0.0.1", "GET", 200, "-", "path");
        
        Alert lowAlert = new Alert(LocalDateTime.now(), ThreatCategory.SUSPICIOUS_IP, Severity.LOW, "127.0.0.1", "system", "low threat", mockLog, 2.0);
        Alert highAlert = new Alert(LocalDateTime.now(), ThreatCategory.SQL_INJECTION, Severity.HIGH, "127.0.0.1", "system", "high threat", mockLog, 7.5);
        Alert criticalAlert = new Alert(LocalDateTime.now(), ThreatCategory.COMMAND_INJECTION, Severity.CRITICAL, "127.0.0.1", "system", "critical threat", mockLog, 9.5);
        
        manager.addAlert(lowAlert);
        manager.addAlert(criticalAlert);
        manager.addAlert(highAlert);
        
        assertEquals(Severity.CRITICAL, manager.pollAlert().getSeverity());
        assertEquals(Severity.HIGH, manager.pollAlert().getSeverity());
        assertEquals(Severity.LOW, manager.pollAlert().getSeverity());
    }
}
```
