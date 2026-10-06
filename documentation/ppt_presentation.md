# POWERPOINT PRESENTATION SLIDES & CONTENT
**Project Title:** Adaptive Cybersecurity Threat Intelligence Engine (ATIE)  
**Academic Defense and Review Presentation Content**

---

## Slide 1: Title Slide
* **Slide Header:** Adaptive Cybersecurity Threat Intelligence Engine (ATIE)
* **Subtitle:** A Real-Time Multi-Format SIEM Processing Pipeline & Threat Simulator
* **Presented By:** [Your Name / Student ID]
* **Under the Guidance of:** [Advisor/Professor Name]
* **Department:** Computer Science and Engineering
* **University:** [University Name]
* **Speaker Notes:** 
  > Good morning, members of the review panel. Today, I will present my final-year capstone project: "Adaptive Cybersecurity Threat Intelligence Engine", or ATIE. This system is a lightweight, high-performance security monitoring platform designed to parse multi-format logs, detect real-time threats using custom data structures, and prioritize alert queues.

---

## Slide 2: Project Overview & Objectives
* **Slide Header:** Project Overview & Objectives
* **Bullet Points:**
  - **Goal:** Develop a standalone, zero-dependency threat detection pipeline using Java 17.
  - **In-Memory Analytics:** Utilize optimized string matching structures (Trie, Boyer-Moore) to replace slow regex-heavy parsers.
  - **Stateful Analysis:** Implement sliding window queues to detect brute force attacks and credential stuffing.
  - **Dynamic Statistics:** Apply moving Z-Score calculations to flag anomalous traffic spikes.
  - **Prioritization:** Deploy a thread-safe priority queue sorting mechanism to rank incoming alerts.
* **Speaker Notes:**
  > The primary goal of ATIE is to provide real-time threat detection and prioritization without the indexing latencies of database-centric SIEM platforms. We achieve this by moving the parsing, signature-matching, and correlation logic into memory using custom algorithms.

---

## Slide 3: Problem Statement & Motivation
* **Slide Header:** Problem Statement & Motivation
* **Bullet Points:**
  - **Log Volumetrics:** Modern servers generate thousands of lines of text logs per second.
  - **Formatting Silos:** Telemetry formats vary widely across Apache access requests, Linux syslogs, and Windows event audits.
  - **Detection Latency:** Traditional SIEM engines rely on relational databases or indexing search engines (e.g., Elasticsearch), causing alerts to lag behind active attacks.
  - **Static Rules Limitation:** Fixed threshold alarms fail to adapt to normal business traffic variations, causing high numbers of false alerts.
* **Speaker Notes:**
  > Security teams face high volumes of logs from diverse sources. Traditional tools struggle with the ingestion overhead of regex parsing and database indexing, which can delay threat detection. ATIE addresses this by processing logs in memory before writing to disk.

---

## Slide 4: Existing System vs. Proposed System
* **Slide Header:** Architecture Comparison
* **Comparison Table:**

| Feature | Existing SIEM Systems | Proposed ATIE System |
|---|---|---|
| **Architecture** | Database/Search-centric indexing | Standalone in-memory stream pipeline |
| **Parsing Engine** | Regular Expression matching | Custom-preprocessed structures |
| **Threat Signature** | Iterates over rule databases | Prefix Trie + Boyer-Moore heuristics |
| **Volumetric Auditing** | Static limit thresholds | Moving Z-Score statistic |
| **Alert Priority** | Chronological order queues | Dynamic Risk-Score Priority Queue |

* **Speaker Notes:**
  > Traditional platforms are resource-heavy and use regex-heavy parsing. ATIE replaces this with a lightweight pipeline, custom preprocessed data structures, and adaptive Z-Score thresholds that adjust to traffic patterns.

---

## Slide 5: System Pipeline Architecture
* **Slide Header:** System Pipeline Architecture
* **Visual Flow (Mermaid Description):**
  - **Ingest:** Log files (Apache, Syslog, Windows) are replayed line-by-line via `LogReplaySimulator`.
  - **Factory:** `LogParserFactory` instantiates the matching parser, outputting a structured `LogEntry`.
  - **Analyze:** `ThreatDetectorOrchestrator` runs the log through three parallel engines:
    1. Signature-based (Trie + Boyer-Moore)
    2. Sliding Window (Brute Force/Credential Stuffing)
    3. Z-Score (Traffic volume anomalies)
  - **Prioritize:** Alerts are assigned a dynamic risk score and queued in a thread-safe `PriorityBlockingQueue` inside the `AlertManager`.
  - **Report:** The analyst views alerts on the terminal dashboard and exports reports to Markdown.
* **Speaker Notes:**
  > Here we see the system pipeline. Raw logs are read by the simulator, parsed into Java models, and analyzed in parallel. Triggered alerts are enriched with threat intelligence and routed to a Priority Queue, where they are rendered on the dashboard and compiled into markdown reports.

---

## Slide 6: Signature Matching Algorithms
* **Slide Header:** Custom String Matching: Trie & Boyer-Moore
* **Bullet Points:**
  - **Prefix Trie:**
    - Used for directory paths and URL searches (e.g., `/etc/passwd/`, `/wp-admin/`).
    - Traverses characters in $O(L)$ time, independent of signature database size.
  - **Boyer-Moore Substring Matching:**
    - Used for attack signatures (e.g. `UNION SELECT`, `<script>`).
    - Aligns patterns and matches from right to left, utilizing a pre-computed bad character shift map.
    - Achieves an average time complexity of $O(N/M)$, skipping unnecessary character comparisons.
* **Speaker Notes:**
  > To optimize signature scanning, we split rules between a Trie and Boyer-Moore matchers. The Trie handles prefix paths in $O(L)$ time, while Boyer-Moore uses a bad character shift map to scan payload fields in $O(N/M)$ average-case time.

---

## Slide 7: Stateful Correlation & Anomalies
* **Slide Header:** Brute Force & Volumetric Anomalies
* **Bullet Points:**
  - **Sliding Window Detection:**
    - Tracks failed authentication attempts within a sliding time window (default: 60s).
    - Uses concurrent queues to track failures per IP and Username.
    - Detects credential stuffing and password guessing when failures exceed threshold limit.
  - **Z-Score Anomaly Analyzer:**
    - Groups logs into 5-second intervals.
    - Computes moving mean ($\mu$) and standard deviation ($\sigma$) over a 50-interval baseline.
    - Flags volume spikes when:
      $$Z = \frac{X_{\text{current}} - \mu}{\sigma} > 2.5$$
* **Speaker Notes:**
  > Stateful analysis is split between brute-force tracking and traffic anomaly detection. The Sliding Window tracks authentication failures within a moving time window, while the Z-Score analyzer calculates standard deviations over a baseline history to identify volumetric anomalies.

---

## Slide 8: Threat Intel & Dynamic Scoring
* **Slide Header:** Threat Intelligence & Priority Queueing
* **Bullet Points:**
  - **IP Reputation Check:** Compares log sources against an active blacklist database (`ip_blacklist.txt`).
  - **Risk Score Calculation:**
    $$\text{Risk Score} = \text{Base}(Category) + \text{IP Reputation} + \text{Privileged User} + \text{Status Code}$$
  - **Severity Mapping:** Categorizes alerts into Low, Medium, High, and Critical.
  - **Priority Blocking Queue:**
    - Automatically sorts alerts by severity and risk score.
    - Thread-safe consumer interface preserves heap sorting invariants.
* **Speaker Notes:**
  > Every detected event is scored based on threat category, IP reputation, targeted user account, and web status code. Triggered alerts are stored in a thread-safe Priority Queue, ensuring critical events are displayed first.

---

## Slide 9: Implementation Details & Clean Code
* **Slide Header:** System Design & Implementation
* **Bullet Points:**
  - **SOLID Principles:** Segregated interfaces and factory patterns avoid tight couplings.
  - **Concurreny Model:** Simulator runs on background threads, communicating with the UI via the Observer pattern.
  - **Zero-Dependency Architecture:** Core engine utilizes native Java libraries, ensuring portability.
  - **Robust Exception Handling:** Processing issues are isolated to prevent simulator interruption.
* **Speaker Notes:**
  > The code follows SOLID design principles, dividing responsibilities into distinct modules. Concurrency is managed using thread-safe collections and a background simulator thread, allowing the main CLI dashboard to remain interactive.

---

## Slide 10: Testing & Validation
* **Slide Header:** Validation Strategy & Verification
* **Bullet Points:**
  - **Unit Testing:** Comprehensive test coverage via JUnit 5.
  - **Key Tests Executed:**
    - Trie prefix matches and Boyer-Moore substring searches.
    - Parser extraction correctness across Apache, Syslog, and Windows Event formats.
    - Sliding window queue evictions.
    - Statistical Z-Score triggers.
    - Priority queue sorting behavior.
* **Speaker Notes:**
  > We validated the system using a JUnit 5 test suite. Tests verified the correctness of the Trie, Boyer-Moore matching, log parsers, sliding window queue evictions, Z-Score calculations, and priority queue ordering.

---

## Slide 11: Incident Report Generation
* **Slide Header:** Actionable Reporting & Mitigations
* **Bullet Points:**
  - **Executive Summary:** Summarizes incident statistics, unique source IPs, and target nodes.
  - **Chronological Timeline:** Logs events sequentially.
  - **Mitigation Blueprints:** Generates dynamic recommendations based on active threats:
    - *SQLi:* Parameterized queries, WAF rules.
    - *XSS:* Context-aware HTML escaping, CSP configurations.
    - *Brute Force:* Account lockouts, rate limiting, MFA enforcement.
* **Speaker Notes:**
  > Analysts can export a Markdown incident report containing an executive summary, chronological timeline, and dynamic mitigation recommendations based on the active threat categories detected.

---

## Slide 12: Advantages & Key Features
* **Slide Header:** Engine Advantages
* **Bullet Points:**
  - **High Performance:** Pre-processed string search tables bypass character scans on clean lines.
  - **Dynamic Thresholds:** Moving Z-Score statistics adapt to shifting traffic patterns, minimizing false positives.
  - **Interactive Terminal UI:** Built-in ANSI colors, statistics progress bars, and threat analytics charts.
  - **Portability:** Packageable as a JAR with resource files loaded from the classpath.
* **Speaker Notes:**
  > Key advantages include high-speed parsing via custom string matching, adaptive Z-Score limits, and an interactive ANSI CLI dashboard that displays sorted alerts and statistics in real time.

---

## Slide 13: Future Scope & Enhancements
* **Slide Header:** Future Scope
* **Bullet Points:**
  - **Remote Telemetry Ingestion:** Support direct log collection over UDP/TCP sockets.
  - **ML Integrations:** Train anomaly models using Isolation Forests and Autoencoders.
  - **CEF/LEEF Standards:** Export alerts in standard format for external SIEM integration.
  - **GUI Dashboard:** Build a desktop web interface using React and Spring Boot.
* **Speaker Notes:**
  > For future work, we plan to extend the engine to support remote log collection over network sockets, integrate machine learning models, and implement a web-based frontend GUI dashboard.

---

## Slide 14: Conclusion
* **Slide Header:** Conclusion
* **Summary Points:**
  - Designed and developed a lightweight SIEM engine utilizing Java 17.
  - Replaced standard regex parsing with optimized Trie and Boyer-Moore matching algorithms.
  - Replaced static thresholds with adaptive, statistical Z-Score anomaly detectors.
  - Successfully demonstrated log parsing, priority-based threat alerting, and incident reporting.
* **Speaker Notes:**
  > In conclusion, ATIE demonstrates the efficiency of custom, preprocessed structures in log analysis. By utilizing a Trie for path indexing, Boyer-Moore for payload scans, Z-Score math for anomalies, and a Priority Queue for alert scheduling, we have built a functional SIEM threat detector. Thank you, and I am open to any questions from the panel.
