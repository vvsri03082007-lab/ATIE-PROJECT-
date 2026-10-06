# Adaptive Cybersecurity Threat Intelligence Engine (ATIE)
## Project Problem Statement & Features Document

---

## 1. Problem Statement

### a. Finalized Full Title of Project
**Adaptive Cybersecurity Threat Intelligence Engine (ATIE): A Real-Time, Multi-Format Security Information and Event Management (SIEM) Simulator**

### b. What Problem does the Application Solve & Why is this Needed?

#### **Problems Solved:**
1. **High Ingestion Latency & High CPU Overhead:** 
   Standard enterprise SIEM products (e.g., Splunk, ELK) rely heavily on database indexing and regex engines. This introduces delays in log parsing. ATIE solves this by implementing custom pre-processed data structures—specifically a **Prefix Trie** for directory traversal paths and the **Boyer-Moore String Matching** algorithm for malicious substrings (e.g., SQLi/XSS signatures)—reducing string matching to sub-linear time complexity.
   
2. **Alert Fatigue from Rigid Static Thresholds:** 
   Conventional security firewalls trigger alerts on static limits (e.g., more than 10 requests per minute). This generates false positives during peak business hours and fails to detect low-and-slow brute force attacks. ATIE introduces a dynamic **Z-Score Anomaly Analyzer** that mathematically computes standard deviations of baseline traffic, adapting dynamically to typical traffic behavior.
   
3. **Data Heterogeneity:** 
   Enterprise system components produce logs in mismatched shapes (Apache HTTP logs, Linux Syslogs, Windows CSV Event Logs). ATIE implements a clean factory pattern to normalize various telemetry data streams into unified security objects in memory.

#### **Why This is Needed:**
Modern organizations generate vast volumes of heterogeneous log telemetry every minute. Fast, local edge processing is critical to detect, weight, prioritize, and alert security operations center (SOC) analysts about active threats in real time before logs are written to massive cold storage databases. ATIE acts as a fast, zero-dependency, lightweight SIEM log processor that isolates and prioritizes threat alerts immediately.

---

## 2. Features of the Project

### a. Non-Functional Requirements

#### **i. Console-Based Interface**
The entire application runs inside a command-line interface (CLI) with highly optimized terminal layouts:
* **Interactive Control Menu:** Located in [Main.java](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/Main.java#L90-L102), it displays interactive ANSI-colored options, allowing users to configure sources, adjust parameters, search databases, and watch threat replays.
* **Live Replay Monitoring:** Streams incoming parsed logs in **green** and security alerts in **red** (incorporating an ASCII bell `\u0007` to beep when a `CRITICAL` threat is triggered).
* **Text-Based Visualizations:** Features custom ASCII progress bar graphs showing severity level allocations dynamically:
  ```text
  Severity Distribution Graph:
    LOW        [██████░░░░░░░░░░░░░░]  30% (3 alerts)
    MEDIUM     [██████████░░░░░░░░░░]  50% (5 alerts)
    HIGH       [████░░░░░░░░░░░░░░░░]  20% (2 alerts)
  ```

#### **ii. Fast Execution (Multithreading)**
To guarantee log processing does not lock up the user interface, execution is delegated across multiple execution contexts:
* **Background Threading:** In [LogReplaySimulator.java](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/simulator/LogReplaySimulator.java#L69-L77), log streams are parsed and simulated in a separate execution flow called `LogReplayThread`, preventing UI freezes.
* **Concurrent Collections:** To avoid resource race conditions, thread-safe data structures are used, such as `PriorityBlockingQueue` for priority alert ingestion and `ConcurrentHashMap` inside [AlertManager.java](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/alerting/AlertManager.java#L21-L28) for real-time tracking of threat classifications.

#### **iii. Secure Input**
ATIE prevents terminal input errors and malicious commands:
* **Sanitization:** String input uses `scanner.nextLine().trim()` in [Main.java](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/Main.java#L59) to strip dangerous leading/trailing control characters.
* **Bounds & Type Verification:** When modifying sensitivity parameters (e.g., Z-score standard deviation coefficients, sliding window times), input values are validated to enforce standard bounds (e.g., preventing negative times or zero thresholds) and handle parsing errors gracefully.

#### **iv. Error Handling (Exceptions)**
Robust recovery mechanisms prevent program crashes:
* **File System Operations:** [Main.java](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/Main.java#L444-L450) wraps incident report exports in a `try-catch` catching `IOException` parameters, gracefully reporting failures to the user.
* **Fallback Systems:** In [ThreatIntelEngine.java](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/intel/ThreatIntelEngine.java#L29-L50), if the default reputation list file `ip_blacklist.txt` is missing or corrupted, the system catches the exception and populates hardcoded default threat telemetry to keep the engine operational.

---

### b. Functional Requirements (CRUD Operations on Records)

The application supports a full lifecycle of database-equivalent operations (CRUD) for threat signatures, alerts, and settings.

| Requirement | CRUD Operation | Implementation in ATIE Codebase |
| :--- | :---: | :--- |
| **i. Add Records** | **Create** | <ul><li>**Log Ingestion:** Stream parsing dynamically inserts alert logs into the core state via [AlertManager.addAlert(alert)](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/alerting/AlertManager.java#L41-L51).</li><li>**Intel Addition:** Security operators can add new malicious IP addresses directly into the active reputation database utilizing [ThreatIntelEngine.addIPToBlacklist(ip)](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/intel/ThreatIntelEngine.java#L77-L81).</li></ul> |
| **ii. Search Records** | **Read** | <ul><li>**Alert History Search:** Option 6 in the main menu enables users to query logged alerts based on **Attacking Source IP**, **Threat Category**, or **Severity Level** using [Main.searchAlerts()](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/Main.java#L336-L414).</li><li>**Reputation Lookups:** Option 4 -> 1 allows users to search the threat intelligence index to check if a specific IP address is currently blacklisted.</li></ul> |
| **iii. Update Records** | **Update** | <ul><li>**Parameter Modification:** Users can dynamically modify active detection rules (sliding time windows and brute force trigger thresholds) in real time using [Main.configureThresholds()](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/Main.java#L205-L246).</li><li>**Dynamic Scoring:** The composite threat score updates dynamically according to context indicators (e.g., target user role or status code matching).</li></ul> |
| **iv. Delete Records** | **Delete** | <ul><li>**Reset & Clear:** Using Option 7 ([Main.clearAlerts()](file:///C:/Users/vvsri/Downloads/java%20project%20final/src/main/java/com/cybersecurity/engine/Main.java#L416-L426)), analysts can completely clear the current session's log database, emptying the priority queues and resetting statistics.</li></ul> |
