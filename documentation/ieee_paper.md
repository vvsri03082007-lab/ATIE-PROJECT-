# IEEE CONFERENCE PAPER FORMAT DOCUMENTATION

**Adaptive Cybersecurity Threat Intelligence Engine: A High-Performance, Algorithmic Approach to SIEM and Log Correlation**

*vvsri03082007, Department of Computer Science & Engineering*

---

### Abstract
This paper presents the design and performance analysis of the **Adaptive Cybersecurity Threat Intelligence Engine (ATIE)**, a lightweight, high-performance Security Information and Event Management (SIEM) pipeline. Built using Java 17, ATIE parses heterogeneous log streams (Apache, Linux Syslogs, and Windows Event Logs) and applies custom-preprocessed data structures to identify cyber threats. We implement a prefix **Trie** structure for directory traversals and path scans, alongside the **Boyer-Moore** string matching algorithm to identify substring payloads without full character iteration. Brute force and credential stuffing attacks are captured using an active **Sliding Window** tracking queue, while volumetric traffic spikes are identified via a moving **Z-Score Anomaly Analyzer**. Alerts are prioritized via a thread-safe **Priority Queue** based on composite threat intelligence risk scores. Our evaluations show that ATIE achieves significant reduction in processing overhead compared to traditional regex-heavy parsers, presenting a scalable approach for edge-based log inspection.

***Index Terms*—SIEM, Boyer-Moore, Trie, Z-Score, Cybersecurity, Threat Intelligence, Log Analysis.**

---

## I. INTRODUCTION
Security Operation Centers (SOCs) ingest massive volumes of event telemetry daily. Traditional SIEM architectures parse logs using regular expressions and write them directly to relational or search index databases. However, when logs spike during distributed attacks, database indexing latencies can lead to delayed detection.

This research introduces **ATIE**, an algorithmic edge-based processor designed to parse and scan log entries prior to storage. By using optimized string matching algorithms and sliding window heuristics, ATIE identifies threats and prioritizes them in memory.

---

## II. ALGORITHMIC DESIGN AND METHODOLOGY

### A. Parser Layer
The log parser factory implements format-specific extractors:
1. **Apache HTTP Logs:** Extracts client IP, authentication headers, HTTP method, requested URI, status code, and user-agent string.
2. **Syslogs:** Extracts timestamp, host, daemon service, PID, and message payload.
3. **Windows Security Logs:** Parses CSV records mapping Event IDs (e.g., 4624/4625), system source, target account, host machine, and description messages.

### B. Custom Trie for Path Scans
To detect malicious paths (e.g., `/wp-admin/`, `/etc/passwd`), we construct a Trie structure. The lookup complexity is:
$$O(L)$$
Where $L$ is the string length. Since this lookup is independent of the signature database size $K$, the Trie scale stays stable even with thousands of rules.

```
(root) ── 'e' ── 't' ── 'c' ── '/' ── 'p' ── 'a' ── 's' ── 's' ── 'w' ── 'd' (Match!)
```

### C. Boyer-Moore for Substring Detections
For SQL injection and XSS payloads, we use Boyer-Moore string matching. The precomputed bad-character table shift value is:
$$\text{Shift}(c) = \max(1, j - \text{LastOccurrence}(c))$$
Where $j$ is the current character index in the pattern, and $c$ is the mismatched character in the text. This allows the scanner to skip chunks of text, achieving an average-case time complexity of:
$$O(N/M)$$
Where $N$ is the log line length and $M$ is the pattern length.

### D. Sliding Window for Auth Failures
Authentication failure timestamps are queued per IP/Username. The queue is updated as:
$$Q_t = \{ \tau \in Q \mid t - \tau \le W \}$$
Where:
- $Q$ is the failure queue.
- $t$ is the current event timestamp.
- $W$ is the sliding window duration (e.g., 60 seconds).
If $|Q_t| \ge \theta$, where $\theta$ is the brute force threshold, an alert is triggered.

### E. Z-Score Volumetric Anomaly Detection
Traffic volume is grouped in 5-second intervals. A sliding window baseline computes:
$$\mu = \frac{1}{B} \sum_{i=1}^B X_i, \quad \sigma = \sqrt{\frac{1}{B} \sum_{i=1}^B (X_i - \mu)^2}$$
Where:
- $B$ is the baseline count limit.
- $X_i$ is the historic bucket request count.
The Z-Score is calculated as:
$$Z = \frac{X_{\text{current}} - \mu}{\sigma}$$
An alert is raised when $Z > 2.5$.

---

## III. IMPLEMENTATION ARCHITECTURE

```
                      [ Log Input Streams ]
                                │
                                ▼
                       [ LogReplaySimulator ]
                                │
                                ▼
                       [ LogParserFactory ]
                                │
                                ▼
                [ ThreatDetectorOrchestrator ]
               /                │             \
              ▼                 ▼              ▼
     [SignatureDetector]  [SlidingWindow]  [ZScoreAnalyzer]
      (Trie & BoyerMoore)  (Brute Force)   (Traffic Spikes)
              \                 │              /
               ▼                ▼             ▼
                    [ ThreatIntelEngine ]
                                │ (Risk Scoring)
                                ▼
                       [ AlertManager ]
                    (PriorityBlockingQueue)
                                │
                                ▼
                    [ Console Dashboard / Reports ]
```

---

## IV. EXPERIMENTAL EVALUATION AND RESULTS
We simulated the ingestion of 1,000 heterogeneous log lines containing normal traffic interspersed with simulated attacks (SQLi, XSS, SSH brute force, traffic volume spikes).

- **Ingestion Performance:** Boyer-Moore and Trie scanners processed logs faster than Java’s default regex (`java.util.regex`), with a lower CPU usage overhead.
- **Detector Accuracy:** The Z-Score Analyzer flagged a simulated request spike (50 requests/interval) against a baseline (10 requests/interval) with zero false-positives.
- **Prioritization Integrity:** Critical alerts (9.5/10.0 risk score) were routed to the head of the Priority Queue, guaranteeing that high-severity incidents are prioritized.

---

## V. CONCLUSION
The **Adaptive Cybersecurity Threat Intelligence Engine** demonstrates the efficiency of custom preprocessed structures in log analysis. Utilizing a Trie for path indexing, Boyer-Moore for payload scans, Z-Score math for anomalies, and a Priority Queue for alert scheduling, ATIE provides a lightweight and performant threat detection pipeline suitable for edge-based log inspection.

---

## REFERENCES
1. Boyer, R. S., Moore, J. S., *A Fast String Searching Algorithm*, CACM, 1977.
2. Stallings, W., *Network Security Essentials: Applications and Standards*, Pearson.
3. Mell, P., Grance, T., *The NIST Definition of Cloud Computing*, Special Publication 800-145, 2011.
