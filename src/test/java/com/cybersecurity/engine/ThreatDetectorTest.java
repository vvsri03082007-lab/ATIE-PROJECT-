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

        // Test prefix
        assertEquals(ThreatCategory.DIRECTORY_TRAVERSAL, trie.searchPrefixOf("/etc/passwd/somefile"));
        assertNull(trie.searchPrefixOf("/etc/var"));

        // Test any substring prefix
        assertEquals(ThreatCategory.MALICIOUS_URL, trie.searchAnySubstringPrefix("/site/wp-admin/install.php"));
        assertEquals(ThreatCategory.DIRECTORY_TRAVERSAL, trie.searchAnySubstringPrefix("/viewer.php?file=../../etc/passwd"));
        assertNull(trie.searchAnySubstringPrefix("/index.html"));
    }

    @Test
    public void testBoyerMooreMatcher() {
        BoyerMooreMatcher matcher = new BoyerMooreMatcher("UNION SELECT");

        // Simple check
        assertTrue(matcher.search("GET /index.php?id=1 UNION SELECT * FROM users") >= 0);
        assertTrue(matcher.search("union select id from customers") >= 0); // case insensitive check
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
        assertEquals(0, entry.getStatusCode()); // Failure
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
        assertEquals(0, entry.getStatusCode()); // 4625 is failure
        assertEquals("WINDOWS", entry.getLogType());
    }

    @Test
    public void testSlidingWindowBruteForce() {
        SlidingWindowDetector detector = new SlidingWindowDetector(60, 3); // 3 failures in 60s
        
        LocalDateTime now = LocalDateTime.now();
        LogEntry fail1 = new LogEntry("raw", "WINDOWS", now, "192.168.1.1", "4625", 0, "user1", "Failed");
        LogEntry fail2 = new LogEntry("raw", "WINDOWS", now.plusSeconds(5), "192.168.1.1", "4625", 0, "user1", "Failed");
        LogEntry fail3 = new LogEntry("raw", "WINDOWS", now.plusSeconds(10), "192.168.1.1", "4625", 0, "user1", "Failed");
        
        assertNull(detector.scan(fail1));
        assertNull(detector.scan(fail2));
        
        // Third failure should trigger brute force
        SlidingWindowDetector.Result result = detector.scan(fail3);
        assertNotNull(result);
        assertEquals(ThreatCategory.BRUTE_FORCE, result.getCategory());
        assertTrue(result.getMessage().contains("Brute Force detected"));
    }

    @Test
    public void testZScoreAnomalyDetection() {
        ZScoreAnalyzer analyzer = new ZScoreAnalyzer(2.0); // low threshold for testing
        
        LocalDateTime time = LocalDateTime.of(2026, 6, 24, 18, 0, 0);
        
        // Load a stable baseline of 5 buckets: count = 10, 10, 10, 10, 10
        // Group logs into 5-second windows. 
        // We simulate feeding 10 logs for bucket 1, 10 for bucket 2, etc.
        for (int b = 0; b < 6; b++) {
            LocalDateTime bucketStart = time.plusSeconds(b * 5);
            for (int i = 0; i < 10; i++) {
                analyzer.analyze(new LogEntry("raw", "APACHE", bucketStart.plusSeconds(1), "127.0.0.1", "GET", 200, "-", "path"));
            }
        }
        
        // Ensure baseline is recorded
        assertTrue(analyzer.getBaselineHistory().size() >= 5);
        
        // Feed a spike: 50 requests in the next bucket
        ZScoreAnalyzer.AnomalyResult result = null;
        LocalDateTime spikeTime = time.plusSeconds(30);
        for (int i = 0; i < 50; i++) {
            ZScoreAnalyzer.AnomalyResult r = analyzer.analyze(new LogEntry("raw", "APACHE", spikeTime.plusSeconds(1), "127.0.0.1", "GET", 200, "-", "path"));
            if (r != null) {
                result = r;
            }
        }
        
        // Trigger next bucket boundary to evaluate the spike bucket
        // Spike should have been evaluated as a positive anomaly!
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
        
        // Pull alerts one by one and check if they sort correctly
        assertEquals(Severity.CRITICAL, manager.pollAlert().getSeverity());
        assertEquals(Severity.HIGH, manager.pollAlert().getSeverity());
        assertEquals(Severity.LOW, manager.pollAlert().getSeverity());
    }
}
