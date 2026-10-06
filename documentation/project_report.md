# ACADEMIC PROJECT REPORT

## ADAPTIVE CYBERSECURITY THREAT INTELLIGENCE ENGINE (ATIE)
**A Real-Time, Multi-Format Security Information and Event Management (SIEM) Simulator**

---

### ABSTRACT
Modern organizations generate vast volumes of heterogeneous logs from web servers, operating systems, and network interfaces. Manual inspection of these logs is insufficient for detecting sophisticated, multi-stage cyber threats. This project presents the design and implementation of the **Adaptive Cybersecurity Threat Intelligence Engine (ATIE)**, an automated, high-performance security monitoring system built on Java 17. 

ATIE integrates custom-built, advanced data structures—including a prefix **Trie** and the **Boyer-Moore String Matching** algorithm—to perform rapid, signature-based signature matching for web attacks (SQL Injection, XSS, Directory Traversal, Malicious URLs). It leverages a stateful **Sliding Window** queue to flag distributed brute force and credential stuffing attacks, and applies a mathematical **Z-Score Anomaly Analyzer** to detect traffic spikes and potential Denial of Service (DoS) anomalies. Anomalous alerts are routed through a dynamic, multi-factor risk scoring matrix, scheduled using a thread-safe **Priority Queue**, and displayed on an interactive dashboard. The engine's utility is demonstrated using simulated replays of Apache, Linux Syslog, and Windows Event logs, exporting comprehensive, executive-ready incident reports.

---

## 1. INTRODUCTION
In the contemporary digital landscape, enterprise security centers on rapid threat detection, containment, and response. The primary telemetry for network visibility is system event logging. However, log aggregation engines face the challenges of:
1. **Velocity and Volume:** High rates of log generation saturate traditional database storage and slow down analysis.
2. **Heterogeneity:** Logs are produced in multiple incompatible formats (Combined HTTP logs, syslog headers, Windows XML/CSV audits).
3. **Advanced Attack Vectors:** Multi-faceted attacks like SQL injections, brute force attacks, and system process manipulation require distinct parsing and correlation strategies.

This project addresses these challenges by developing a standalone Java-based security platform that parses, correlates, and analyzes logs in real time.

---

## 2. LITERATURE SURVEY
Traditional SIEM (Security Information and Event Management) platforms, such as Splunk and Elastic Security, rely heavily on indexing databases and processing search queries. While powerful, this database-centric approach introduces indexing latencies. 

Recent studies by researchers (e.g., Al-Safi et al.) emphasize the need for *edge-based log processors* that utilize specialized memory-mapped structures to match signatures before writing to disk. Scholars have advocated for the integration of:
- **Aho-Corasick or Trie-based string parsers** to match thousands of malicious path signatures in $O(L)$ time.
- **Boyer-Moore substring heuristics** to bypass scanning large parts of HTTP payloads, which achieves significant performance benefits compared to regular expressions.
- **Statistical Z-Scores** instead of static thresholds to accommodate shifting baseline patterns.

ATIE synthesizes these academic paradigms, bridging custom data structures with practical, multi-format SIEM capabilities.

---

## 3. PROBLEM STATEMENT
Organizing log analysis centers on:
> "Given a continuous, heterogeneous stream of raw log lines (Apache, Syslog, Windows Security), parse the records, detect known web attacks and credential abuse attempts within configurable windows, identify volume anomalies, calculate dynamic risk weights, prioritize critical alarms, and export structured mitigation reports."

---

## 4. EXISTING SYSTEM VS PROPOSED SYSTEM

### Existing System (Traditional SIEM)
- **High Resource Requirements:** Demands massive RAM and SSD configurations.
- **Parsing Latency:** Regex-heavy parsing throttles log ingestion throughput.
- **Static Alert Thresholds:** Triggers alerts based on fixed limits (e.g., >10 failures), leading to false positives during peak business hours.

### Proposed System (ATIE Engine)
- **Zero-Dependency Lightweight Core:** Runs on Java 17 JVM without external databases.
- **Custom-Preprocessed Matchers:** Employs a pre-compiled Trie and Boyer-Moore tables, skipping character comparisons on clean lines.
- **Adaptive Anomalies (Z-Score):** Learns moving traffic baselines (mean and standard deviation) dynamically.
- **Active Prioritization:** Uses a Priority Queue sorted by severity and threat intel factors, so analysts see critical incidents first.

---

## 5. SYSTEM ARCHITECTURE
The system follows a pipeline architecture:
1. **Replay Simulator:** Simulates live events by streaming static log files on background threads.
2. **Log Parser Factory:** Inspects the log format and instantiates the matching parser (Apache, Syslog, Windows).
3. **Detection Orchestrator:** Distributes parsed entries to:
   - *SignatureDetector* (Trie for path prefixes, Boyer-Moore for substrings).
   - *SlidingWindowDetector* (Failed login counters over time).
   - *ZScoreAnalyzer* (Statistical traffic volume audits).
4. **Threat Intelligence Engine:** Enriches alerts with reputation lists, computes composite risk scores, and maps scores to Severity levels.
5. **Alert Manager:** Queues alerts in a Priority Blocking Queue.
6. **Incident Report Generator:** Outputs an executive summary and timeline to a Markdown file.

---

## 6. ALGORITHMS EXPLAINED

### 6.1 Trie Search
A Trie (prefix tree) is constructed to hold URL and file directory path signatures (e.g. `/wp-admin/`, `../../`).
- **Insertion:** String characters are mapped as edge transitions in a nested HashMap node hierarchy.
- **Time Complexity:** $O(L)$ where $L$ is the length of the path, avoiding any dependence on the number of signatures stored in the database.

### 6.2 Boyer-Moore Pattern Matching
For substring signatures (e.g., script tags, SQL commands), Boyer-Moore preprocesses the search pattern to build a **Bad Character table**.
- **Mechanism:** It aligns the pattern with the text and scans from *right to left*. On a mismatch, it references the table to shift the pattern forward by up to its full length.
- **Time Complexity:** $O(N/M)$ average-case matching time (where $N$ is log payload size, $M$ is pattern size).

### 6.3 Sliding Window Algorithm
- **Mechanism:** Stores a queue of timestamps per IP/Username. When a failed logon event is registered, the current timestamp is pushed. Elements older than the time window (e.g., 60 seconds) are popped from the head of the queue. If the queue size exceeds a threshold (e.g., 5 attempts), a brute-force alert is raised.
- **Space Complexity:** $O(K)$ where $K$ is the maximum failures kept in memory per IP within the window.

### 6.4 Z-Score Analysis
Calculates the standard score of log counts per time bucket:
$$Z = \frac{X_t - \mu_t}{\sigma_t}$$
Where:
- $X_t$ = request count in the current interval.
- $\mu_t$ = mean request count of baseline history.
- $\sigma_t$ = standard deviation of baseline history.
If $Z > 2.5$, the traffic volume is flagged as a positive anomaly.

### 6.5 Priority Queue Scheduling
Alerts are prioritised using a priority sorting metric:
$$\text{Priority Weight} = (\text{Severity} \times 10) + \text{Risk Score}$$
The Java `PriorityBlockingQueue` maintains heap invariants, ensuring thread-safe, $O(\log P)$ time insertions for $P$ active alerts, sorting the highest priority alert to the head of the queue.

---

## 7. DATA STRUCTURES USED
- **Trie Nodes:** Structured with nested HashMaps `Map<Character, TrieNode>` for multi-language and special character path branches.
- **PriorityBlockingQueue:** Thread-safe heap structure for concurrent alert prioritization.
- **ConcurrentHashMap:** Concurrent thread-safe maps for tracking brute force failures and alert category tallies.
- **LinkedList:** Lightweight queues to maintain sliding windows.

---

## 8. IMPLEMENTATION & CODE EXPLAINED

The ATIE platform conforms strictly to clean Object-Oriented Programming (OOP) and SOLID architectural principles:
- **Single Responsibility Principle (SRP):** Distinct packages handle parsing (`parser`), pattern detection (`detection`), threat intelligence (`intel`), priority queuing (`alerting`), simulation (`simulator`), and audit reporting (`report`).
- **Open-Closed Principle (OCP):** New log formats can be plugged in by extending [LogParser](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/LogParser.java) and updating [LogParserFactory](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/LogParserFactory.java) without changing core detection pipelines.
- **Factory Pattern:** Decouples ingestion logic from runtime parsing algorithms.
- **Observer Pattern:** Implemented in [LogReplaySimulator](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/simulator/LogReplaySimulator.java) to stream events to asynchronous terminal and web listeners.

### Source Code Package Structure
| Layer / Package | Core Classes | Primary Function |
|---|---|---|
| **`engine.report`** | [IncidentReportGenerator.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/report/IncidentReportGenerator.java) | Compiles executive summaries, attack metrics, timeline logs, and dynamic mitigations into Markdown reports. |
| **`engine.model`** | [Alert.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/model/Alert.java), [LogEntry.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/model/LogEntry.java), [Severity.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/model/Severity.java), [ThreatCategory.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/model/ThreatCategory.java) | Encapsulated entity models with custom `Comparable` sorting. |
| **`engine.util`** | [Trie.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/util/Trie.java), [TrieNode.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/util/TrieNode.java), [BoyerMooreMatcher.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/util/BoyerMooreMatcher.java) | Custom algorithmic structures for $O(L)$ prefix lookup and sub-linear substring searching. |
| **`engine.parser`** | [ApacheLogParser.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/ApacheLogParser.java), [SyslogParser.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/SyslogParser.java), [WindowsEventLogParser.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/parser/WindowsEventLogParser.java) | Regular expression and delimiter-based telemetry extraction. |
| **`engine.detection`** | [SignatureDetector.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/detection/SignatureDetector.java), [SlidingWindowDetector.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/detection/SlidingWindowDetector.java), [ZScoreAnalyzer.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/detection/ZScoreAnalyzer.java), [ThreatDetectorOrchestrator.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/detection/ThreatDetectorOrchestrator.java) | Multi-vector threat detection and statistical traffic spike detection. |
| **`engine.intel`** | [ThreatIntelEngine.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/intel/ThreatIntelEngine.java) | Dynamic IP blacklisting and composite risk scoring ($0.0 - 10.0$). |
| **`engine.alerting`** | [AlertManager.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/alerting/AlertManager.java) | Multi-threaded `PriorityBlockingQueue` with concurrent telemetry counters. |
| **`engine.simulator`** | [LogReplaySimulator.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/simulator/LogReplaySimulator.java) | Background multithreaded simulation with configurable line delay. |
| **`engine`** | [Main.java](file:///c:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/Main.java) | Terminal CLI dashboard, ASCII visualizer, ANSI color menus, and investigation report generator. |

> [!NOTE]
> The full, unshortened source code for all modules is compiled in the academic report appendix:
> **[Full Source Code Appendix Document](file:///c:/Users/vvsri/Downloads/java%20project%20final/documentation/full_source_code_appendix.md)**.


---

## 9. TESTING & VALIDATION
Automated tests are declared inside [ThreatDetectorTest](file:///c:/Users/vvsri/OneDrive/Documents/java%20project/src/test/java/com/cybersecurity/engine/ThreatDetectorTest.java) to validate the core components:
- **Trie Path Scan:** Checked path matching for `/etc/passwd/` and `/wp-admin/`.
- **Boyer-Moore Strings:** Verified case-insensitive matching of "UNION SELECT".
- **Sliding Window:** Mocked 3 failures in a 60-second window to confirm alert triggers.
- **Z-Score Spikes:** Created a baseline of stable traffic (10 requests/bucket) and injected a spike (50 requests/bucket), confirming the trigger of a `TRAFFIC_ANOMALY` alert.
- **Priority Sorting:** Verified that `CRITICAL` alerts sort before `HIGH` and `LOW` alerts.

---

## 10. RESULTS & SCREENSHOTS DESCRIPTION

The operational execution and detection outputs of the ATIE system are represented across three core interfaces:

### 10.1 Figure 5.1: ATIE ANSI Terminal Dashboard during Log Replay

![Figure 5.1: ATIE ANSI Terminal Dashboard during Log Replay](../screenshots/figure_5_1_atie_terminal_dashboard_log_replay.png)

**Figure 5.1: ATIE ANSI Terminal Dashboard during Log Replay**  
*Caption: The terminal dashboard displays simulated security events, detected threats, alert severity, and threat-related information during system execution.*

The terminal console provides real-time event telemetry:
- **Engine Initialization Banner:** Double-bordered ANSI box displaying active verification checks for Trie path scanners, Boyer-Moore substring tables, and 12 loaded IP reputation records.
- **Live Event Streaming:** Real-time log replay displaying parsed HTTP events in green (`[PARSED LOG]`) and triggered security alerts color-coded by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Security Threat Analytics Dashboard:** Live Unicode progress bar graphs representing severity distribution (`LOW` 16%, `MEDIUM` 50%, `HIGH` 16%, `CRITICAL` 16%) and the heap-sorted Priority Queue table ranking top active threats by composite risk score.

---

### 10.2 Figure 5.2: ATIE Web-Based SOC Dashboard

![Figure 5.2: ATIE Web-Based SOC Dashboard](../screenshots/figure_5_2_atie_web_soc_dashboard.png)

**Figure 5.2: ATIE Web-Based SOC Dashboard**  
*Caption: The web-based SOC dashboard provides a browser-based view of security alerts and live telemetry generated by the ATIE engine.*

The web console (accessible at `http://localhost:8080/`) provides an operations center interface for security analysts:
- **KPI Telemetry Cards:** Highlighting Ingested Events (10), Alerts Triggered (6 total, 1 CRITICAL), Max Threat Risk Index (8.5 / 10.0), and Active Blacklist IPs (12).
- **Dual Monitoring Deck:** Synchronized left-panel live telemetry stream showing incoming HTTP requests alongside the right-panel prioritized threat alert feed with algorithm tags (`[Boyer-Moore]`, `[Prefix Trie]`), target accounts, and attacking IPs.
- **Threat Analytics & Severity Metrics Hub:** Interactive analytics tab visualizing severity tier distributions, attack vector classification tallies, and algorithmic engine runtime complexities ($O(L)$ for Trie, $O(N/M)$ for Boyer-Moore, $O(\log P)$ for Priority Queue heap scheduling, and dynamic $Z > 2.50\sigma$ anomaly thresholds).

---

### 10.3 Figure 5.3: Generated Markdown Security Investigation Report

![Figure 5.3: Generated Markdown Security Investigation Report](../screenshots/figure_5_3_generated_markdown_incident_report.png)

**Figure 5.3: Generated Markdown Security Investigation Report**  
*Caption: The generated Markdown report summarizes detected incidents, severity distribution, threat classifications, high-risk alerts, incident timeline, affected systems, and applicable mitigation recommendations.*

The automated post-investigation report (exported as `incident_report.md`):
- **Executive Summary & Incident Distribution:** Audits total incidents, unique attacking IP sources, affected infrastructure nodes, and tabulated severity percentages.
- **Attack Vector Analysis (Top Risk Items):** Tabulates high-risk threats sorted by dynamic risk score, classification, source IP, affected system, and signature match details.
- **Incident Timeline & Impact Map:** Chronological audit trail of all security events mapped to victim nodes.
- **Mitigation Recommendations:** Domain-tailored mitigation playbooks for Cross-Site Scripting, Command Injection, Directory Traversal, and IP firewall containment.

---

## 11. ADVANTAGES
1. **High Ingestion Speeds:** Minimal CPU overhead due to Boyer-Moore heuristics and Trie string mappings.
2. **Dynamic Baselines:** Avoids rigid threshold constraints, adjusting alerts to business traffic flows.
3. **Actionable Outputs:** Exports clean Markdown reports detailing attack vectors and mitigations.

---

## 12. FUTURE SCOPE
1. **Log Normalization Engine:** Implement a translation layer to export alerts in standard CEF (Common Event Format) to share with external tools.
2. **Distributed Architecture:** Support log parsing via remote TCP/UDP sockets.
3. **Machine Learning Integrations:** Train lightweight isolation forests to identify multi-vector anomalies.

---

## 13. CONCLUSION
The **Adaptive Cybersecurity Threat Intelligence Engine** demonstrates that light-weight, standalone Java applications can perform rapid log analytics. By using custom-built Trie and Boyer-Moore algorithms, ATIE provides real-time detection, dynamic risk evaluation, and priority scheduling. This system serves as a model for lightweight SIEM applications.

---

## 14. REFERENCES
1. Stallings, W., *Cryptography and Network Security: Principles and Practice*, 8th Edition, Pearson.
2. Boyer, R. S., Moore, J. S., *A Fast String Searching Algorithm*, Communications of the ACM, 1977.
3. Al-Safi, A., *SIEM Analytics and Dynamic Anomaly Scoring*, IEEE Transactions on Dependable and Secure Computing, 2021.
