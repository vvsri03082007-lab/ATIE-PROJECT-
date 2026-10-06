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

    /**
     * Loads threat signatures from signatures.txt in the classpath resources.
     */
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

                    // If pattern contains path-like characters or is short, insert in Trie.
                    // Otherwise, load into Boyer-Moore matchers.
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

    /**
     * Fallback signatures if resources are not accessible.
     */
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

    /**
     * Inspects a log entry payload for signature matches.
     *
     * @param entry The LogEntry to scan.
     * @return The detected ThreatCategory, or null if no signature matches.
     */
    public DetectionResult scan(LogEntry entry) {
        String content = entry.getPayload();
        if (content == null || content.isEmpty()) {
            return null;
        }

        // 1. Check Trie for path/prefix matches
        ThreatCategory trieCategory = pathTrie.searchAnySubstringPrefix(content);
        if (trieCategory != null) {
            return new DetectionResult(trieCategory, "Trie prefix signature matched in payload.");
        }

        // 2. Check Boyer-Moore Matchers for payload patterns
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
