# ATIE: Adaptive Threat Intelligence Engine 🛡️⚡

A high-performance, modular Java-based Security Information and Event Management (SIEM) engine and Security Operations Center (SOC) dashboard.

![Java](https://img.shields.io/badge/Java-17%2B-orange?style=flat&logo=openjdk)
![Maven](https://img.shields.io/badge/Maven-3.9%2B-blue?style=flat&logo=apachemaven)
![License](https://img.shields.io/badge/License-Academic-green)

---

## 🌟 Overview

The **Adaptive Threat Intelligence Engine (ATIE)** ingests, parses, correlates, and analyzes security telemetry in real time. It detects cyber threats ranging from brute-force authentication attacks to advanced SQL injections, path traversals, cross-site scripting (XSS), port scans, and volumetric traffic anomalies using algorithmic data structures and statistical methods.

### Key Capabilities
- 🚀 **High-Throughput Log Parsing**: Decodes Apache HTTP access logs, Linux Syslog, and Windows Event logs with robust validation.
- 🔍 **Algorithmic Threat Detection**:
  - **Boyer-Moore String Search** for sublinear pattern matching against web attack signatures (SQLi, XSS, Directory Traversal).
  - **Trie Prefix Lookups** for $O(L)$ CIDR & IP reputation checking.
  - **Sliding Window Time-Series Analysis** for brute force and rate-based intrusion attempts.
  - **Z-Score Statistical Anomaly Detection** for volumetric traffic spikes and DDoS early warning.
- 🌐 **Real-Time SOC Web Dashboard**:
  - Embedded zero-dependency HTTP server with **Server-Sent Events (SSE)** streaming.
  - Live attack alerts, threat severity metrics, and real-time log replay.
  - Threat intelligence management (reputation blacklist updates).
  - Custom raw log ingestion and instant threat analysis.
- 💻 **Interactive ANSI Terminal Console**: Full CLI dashboard for operators with live log simulation controls.
- 📑 **Automated Incident Reporting**: Exports comprehensive Markdown & HTML post-incident investigation reports with mitigation recommendations.

---

## 📁 Project Structure

```
├── src/
│   ├── main/
│   │   ├── java/com/cybersecurity/engine/
│   │   │   ├── alerting/      # Alert queue & manager (PriorityBlockingQueue)
│   │   │   ├── detection/     # Threat orchestrator, SignatureDetector, SlidingWindow, ZScore
│   │   │   ├── intel/         # Threat intelligence engine & reputation lists
│   │   │   ├── model/         # Alert, LogEntry, Severity, ThreatCategory models
│   │   │   ├── parser/        # Apache, Syslog, Windows Event log parsers & factory
│   │   │   ├── report/        # Markdown & HTML incident report generator
│   │   │   ├── simulator/     # Asynchronous multithreaded log replay simulator
│   │   │   ├── util/          # Trie, TrieNode, BoyerMooreMatcher
│   │   │   ├── web/           # Zero-dependency embedded WebServer & Launcher
│   │   │   └── Main.java      # Interactive CLI entrypoint
│   │   └── resources/
│   │       ├── ip_blacklist.txt
│   │       ├── signatures.txt
│   │       ├── sample_logs/   # Sample datasets for simulation
│   │       └── web/           # SOC Web Console (HTML, CSS, JS)
│   └── test/                  # Unit tests (JUnit 5)
├── documentation/             # Project report, IEEE paper, UML diagrams, presentation
├── screenshots/               # Visual outputs of terminal & web dashboards
├── pom.xml                    # Maven build configuration
├── run-server.bat             # One-click Windows Web Server launcher
└── run-server.ps1             # PowerShell Web Server launcher
```

---

## 🚀 Quick Start

### Prerequisites
- **Java JDK 17+** (JDK 17, 21, or 26)
- **Apache Maven 3.9+** (or use the included wrapper / scripts)

### 1. Compile & Build
```powershell
mvn clean compile
```

### 2. Run the SOC Web Dashboard
Launch the web server using any of the following:

- **Windows Batch**: Double-click or run:
  ```powershell
  .\run-server.bat
  ```
- **PowerShell**:
  ```powershell
  .\run-server.ps1
  ```
- **Direct Java Execution**:
  ```powershell
  java -cp target/classes com.cybersecurity.engine.web.WebServerLauncher
  ```
- **Maven**:
  ```powershell
  mvn exec:java -Dexec.mainClass="com.cybersecurity.engine.web.WebServerLauncher"
  ```

Open your browser at: **[http://localhost:8080/](http://localhost:8080/)**

---

### 3. Run the Interactive CLI Console
```powershell
java -cp target/classes com.cybersecurity.engine.Main
```
Or via Maven:
```powershell
mvn exec:java -Dexec.mainClass="com.cybersecurity.engine.Main"
```

---

## 🧪 Running Automated Tests
```powershell
mvn test
```

---

## 📊 Documentation & Research
- 📄 Comprehensive Project Report: `documentation/project_report.md`
- 📑 IEEE-format Paper: `documentation/ieee_paper.md`
- 🖼️ System Architecture & UML: `documentation/uml_diagrams.md`
- 🎤 Presentation Deck: `documentation/ppt_presentation.md`
- 💡 Viva Q&A Guide: `documentation/viva_qna.md`
