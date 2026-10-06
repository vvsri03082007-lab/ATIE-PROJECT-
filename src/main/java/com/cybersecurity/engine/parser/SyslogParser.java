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
// Concept: Inheritance (Implementing the LogParser interface)
public class SyslogParser implements LogParser {
    // Regex matching standard Linux syslog format
    private static final Pattern SYSLOG_PATTERN = Pattern.compile(
            "^([A-Z][a-z]{2}\\s+\\d+\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+([^:\\[\\s]+)(?:\\[(\\d+)\\])?:\\s+(.*)$"
    );

    // Helpers to extract IP and Username from the message body
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    );
    private static final Pattern USER_PATTERN = Pattern.compile(
            "(?:for|user|by)\\s+([a-zA-Z0-9_.-]+)"
    );

    // Concept: Polymorphism (Overriding the parse contract to implement specific Syslog parsing)
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

        // Normalize spaces in syslog timestamp (handles single-digit days like "Jun  4" -> "Jun 4")
        String normalizedTime = timeStr.replaceAll("\\s+", " ");
        int currentYear = LocalDateTime.now().getYear();
        String fullTimeStr = currentYear + " " + normalizedTime;

        LocalDateTime timestamp;
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy MMM d HH:mm:ss", Locale.ENGLISH);
            timestamp = LocalDateTime.parse(fullTimeStr, formatter);
        } catch (Exception e) {
            timestamp = LocalDateTime.now(); // Fallback
        }

        // Extract IP address from message body, fallback to hostname
        String ipAddress = "127.0.0.1";
        Matcher ipMatcher = IP_PATTERN.matcher(message);
        if (ipMatcher.find()) {
            ipAddress = ipMatcher.group();
        }

        // Extract Username from message body, fallback to SYSTEM or ANONYMOUS
        String userInfo = "SYSTEM";
        Matcher userMatcher = USER_PATTERN.matcher(message);
        if (userMatcher.find()) {
            userInfo = userMatcher.group(1);
            if ("invalid".equalsIgnoreCase(userInfo) && message.contains("invalid user")) {
                // Secondary check for "invalid user oracle"
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

        // Map status code: 0 = failed authentication/error, 1 = success/information
        int statusCode = 1;
        String lowerMessage = message.toLowerCase();
        if (lowerMessage.contains("fail") || lowerMessage.contains("error") || lowerMessage.contains("invalid")) {
            statusCode = 0;
        }

        // Concept: Object (Instantiation of a new LogEntry per parsed syslog line)
        return new LogEntry(
                rawLogLine,
                "SYSLOG",
                timestamp,
                ipAddress,
                service, // requestType represents the service (e.g. sshd, sudo)
                statusCode,
                userInfo,
                message // Payload holds the rest of the message
        );
    }
}
