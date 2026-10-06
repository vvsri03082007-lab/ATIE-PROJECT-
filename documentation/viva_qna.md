# VIVA QUESTIONS AND ANSWERS

This document compiles technical questions and answers designed to prepare you for the final project defense and university viva evaluations for the **Adaptive Cybersecurity Threat Intelligence Engine**.

---

### Q1: What is the main objective of this project?
**A:** The goal is to develop a lightweight, standalone, and high-performance cybersecurity monitoring platform (SIEM) that ingests multi-format logs, parses them in real time, applies custom data structures and statistical algorithms to detect threats, calculates dynamic risk scores, prioritizes alerts, and generates mitigation reports.

### Q2: Why did you implement a custom Trie and Boyer-Moore matcher instead of using Java's built-in Regular Expressions?
**A:** Regular expressions use backtracking engines which have a time complexity that can degrade significantly under complex inputs. 
- A **Trie** allows us to scan for prefix path signatures (like `/etc/passwd/` or `/wp-admin/`) in $O(L)$ time, where $L$ is the string length, independent of the size of the signature database.
- **Boyer-Moore** aligns pattern strings and scans from right to left using a Bad Character shift table, which can skip characters in the text, achieving an average lookup speed of $O(N/M)$ (where $N$ is text size, $M$ is pattern size). This is faster than standard regular expressions when searching for signatures within logs.

### Q3: Explain how the Sliding Window Algorithm works in your Brute Force detection module.
**A:** We track failed logins by maintaining a timestamped queue (`LinkedList`) in a `ConcurrentHashMap` mapped to each IP or Username. When a failed logon event occurs, we record its timestamp and add it to the queue. We then scan the queue from the head, removing any timestamps that are older than our time window (e.g., 60 seconds). If the remaining items in the queue exceed our threshold (e.g., 5 failures), it triggers a brute-force alert.

### Q4: How is Z-Score Analysis applied in your system to detect anomalies?
**A:** The engine groups incoming log counts into 5-second time buckets. We store the log count of the last 50 buckets to establish a moving baseline. When a bucket finishes, we calculate its mean ($\mu$) and standard deviation ($\sigma$) from the baseline. We then calculate the Z-Score of the completed bucket:
$$Z = \frac{\text{Count} - \mu}{\sigma}$$
If the Z-Score exceeds a threshold (e.g., 2.5 standard deviations), it flags the traffic volume spike as an anomaly.

### Q5: Why did you choose a PriorityBlockingQueue for the Alert Manager?
**A:** 
1. **Thread Safety:** The log simulator runs on a separate thread, while the console UI reads alerts from the main thread. A `PriorityBlockingQueue` provides thread-safe operations, preventing race conditions.
2. **Prioritization:** It implements a binary heap that automatically sorts alerts based on their severity and risk score. This ensures that a `CRITICAL` alert is always positioned at the head of the queue to be processed first, regardless of when it arrived.

### Q6: What Design Patterns have you incorporated in the architecture?
**A:**
1. **Factory Pattern:** Implemented in `LogParserFactory` to create the appropriate parser (Apache, Syslog, or Windows) based on log type.
2. **Observer Pattern:** Implemented in `LogReplaySimulator` where listeners register to receive callbacks when a log is parsed, an alert is triggered, or the simulation finishes. This decouples the core engine logic from the CLI console dashboard.
3. **Strategy Pattern:** Implicitly used through the `LogParser` interface, allowing us to swap parsing strategies at runtime.

### Q7: How does the Threat Intelligence Module calculate the composite Risk Score?
**A:** The risk score is a value from 0.0 to 10.0 calculated based on several threat factors:
- **Base Score:** Assigned based on the threat category (e.g., Command Injection = 6.0, SQLi = 5.0).
- **IP Reputation:** Adds 2.5 points if the source IP is matched in our `ip_blacklist.txt` database.
- **User Risk:** Adds 1.5 points if target user accounts are privileged (e.g. `root`, `administrator`, or `SYSTEM`).
- **Web Status Code:** Adds 1.0 points if the HTTP response is 500 (Internal Server Error), which can indicate a successful exploit attempt.
The score is capped at 10.0 and mapped to Severity levels: Low (<4.0), Medium (4.0-5.9), High (6.0-7.9), and Critical (>=8.0).

### Q8: What are the SOLID principles, and how does your project follow them?
**A:**
- **Single Responsibility (SRP):** Classes have single roles. For example, `BoyerMooreMatcher` only handles string matching, and `IncidentReportGenerator` only handles report writing.
- **Open-Closed (OCP):** We can add new log formats (e.g., AWS CloudTrail logs) by writing a new class implementing the `LogParser` interface and adding it to the factory, without modifying existing parsers.
- **Liskov Substitution (LSP):** Any class implementing `LogParser` can be swapped transparently without breaking the factory or simulator.
- **Interface Segregation (ISP):** The `LogParser` interface defines a simple parse contract.
- **Dependency Inversion (DIP):** The orchestrator depends on the abstract `LogParser` interface rather than concrete parser implementations.

### Q9: How does the Z-Score analyzer handle situations where the Standard Deviation ($\sigma$) is 0?
**A:** If standard deviation is 0, it means traffic volume has been constant (e.g., exactly 10 requests per bucket). Division by zero would result in an undefined Z-Score. To handle this, we detect when $\sigma < 0.0001$. If the standard deviation is near zero and the count spikes (e.g., a sudden jump to 15), we manually trigger an anomaly alert with a high risk score, avoiding division by zero errors.

### Q10: How do you read resources in a packaged Maven JAR environment?
**A:** Instead of using standard file paths (`new File("path")`), which can fail once files are packaged inside a JAR, we use:
`getClass().getResourceAsStream("/signatures.txt")`
This loads resource files from the classpath, ensuring the application remains portable.

### Q11: Explain the difference between Credential Stuffing and Brute Force, and how you detect both.
**A:**
- **Brute Force:** A single IP tries multiple passwords against a single account. Detected when a single IP triggers consecutive login failures.
- **Credential Stuffing:** An attacker tests credentials across many user accounts. In this case, failures may originate from multiple IPs, but target the same accounts. We track sliding windows per **IP** and per **Username** to detect both patterns.

### Q12: How did you implement thread-safety in your simulation counters?
**A:** We use thread-safe data structures like `ConcurrentHashMap` for event tracking. In addition, critical write methods in `AlertManager` and `ZScoreAnalyzer` are declared as `synchronized` to prevent state corruption during concurrent access.

### Q13: What happens when a high-severity alert is detected? How does it affect the blacklist?
**A:** When a non-low severity alert triggers, the orchestrator automatically adds the offending IP address to the `ThreatIntelEngine` blacklist. This dynamic blacklisting increases the risk score of any subsequent connections from that IP.

### Q14: How does your Boyer-Moore implementation achieve case-insensitive searches?
**A:** The constructor converts the pattern to lowercase, and the `search()` method converts the input text to lowercase before matching. This ensures case insensitivity without degrading search speeds.

### Q15: What is the space complexity of your Trie implementation?
**A:** The space complexity of a Trie is $O(\Sigma \times N \times M)$, where $\Sigma$ is the alphabet size, $N$ is the number of signatures, and $M$ is the average signature length. Using `HashMap` nodes optimizes space by allocating child pointers dynamically rather than pre-allocating large character arrays.

### Q16: How do you parse dates in Apache logs?
**A:** We use a `DateTimeFormatter` configured with the pattern `"dd/MMM/yyyy:HH:mm:ss Z"` and `Locale.ENGLISH`. Using `ZonedDateTime` handles timezone offsets (e.g. `+0530`) and converts the result to a standardized local time.

### Q17: What was the main challenge you faced during implementation, and how did you resolve it?
**A:** A key challenge was managing console outputs during live log replays. Printing log lines from the background thread interfered with the main dashboard menu. We resolved this by implementing a dedicated "Live Monitoring Mode". In this mode, the program enters a structured wait loop, allowing the simulator thread to write to the console. The user exits this mode by pressing ENTER, restoring clean menu interactions.

### Q18: What JVM version did you use, and what modern features did you leverage?
**A:** We compiled using **Java 17 / Java 26**. We leveraged modern features such as:
- **Switch Expressions:** To simplify mappings, such as translating severities and categories to risk scores.
- **Pattern Matching for Switch:** Used to classify logs.
- **Stream API:** To process collections and compile statistics.

### Q19: How would you scale this system to handle millions of logs per second?
**A:** To scale the architecture:
1. **Message Broker Integration:** Feed logs into a distributed message queue like Apache Kafka.
2. **Horizontal Scaling:** Run multiple instances of the detection orchestrator inside containerized microservices (Docker/Kubernetes).
3. **Offloading History:** Periodically write alert histories to Elasticsearch or ClickHouse rather than maintaining them in-memory.

### Q20: What are the recommended mitigations for directory traversal attacks?
**A:**
1. **Path Canonicalization:** Run `File.getCanonicalPath()` to resolve symbolic links and relative path characters (`..`), validating that the final path remains within the intended target directory.
2. **Access Control Lists (ACLs):** Restrict read permissions on system file directories (e.g. `/etc/`, `/windows/system32/`).
3. **Chroot Jails:** Run the application daemon in a restricted environment to isolate file system access.
