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
// Concept: Inheritance (Implementing the LogParser interface)
public class WindowsEventLogParser implements LogParser {

    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    );

    // Parses account name inside the event description
    private static final Pattern ACCOUNT_NAME_PATTERN = Pattern.compile(
            "Account Name:\\s*([a-zA-Z0-9_.-]+)"
    );

    // Concept: Polymorphism (Overriding the parse contract to implement specific Windows event parsing)
    @Override
    public LogEntry parse(String rawLogLine) throws Exception {
        if (rawLogLine == null || rawLogLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Log line is empty");
        }

        // Split up to 7 parts to handle commas in the message field
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

        // Parse timestamp
        LocalDateTime timestamp;
        try {
            timestamp = LocalDateTime.parse(dateStr + " " + timeStr, DATE_FORMATTER);
        } catch (Exception e) {
            timestamp = LocalDateTime.now(); // Fallback
        }

        // Parse Event ID as the status code
        int eventId = 0;
        try {
            eventId = Integer.parseInt(eventIdStr);
        } catch (NumberFormatException ignored) {}

        // Extract IP address from message body if present
        String ipAddress = "127.0.0.1";
        Matcher ipMatcher = IP_PATTERN.matcher(message);
        if (ipMatcher.find()) {
            ipAddress = ipMatcher.group();
        }

        // Extract specific username from message body if present, fallback to defaultUser
        String userInfo = defaultUser;
        Matcher accountMatcher = ACCOUNT_NAME_PATTERN.matcher(message);
        if (accountMatcher.find()) {
            String match = accountMatcher.group(1);
            if (!match.equalsIgnoreCase("SYSTEM")) {
                userInfo = match;
            }
        }

        // Status mapping: if Event ID is 4625 (Logon Failure), status is 0. Otherwise 1 (or other status).
        int statusCode = (eventId == 4625) ? 0 : 1;

        // Concept: Object (Instantiation of a new LogEntry per parsed Windows event line)
        return new LogEntry(
                rawLogLine,
                "WINDOWS",
                timestamp,
                ipAddress,
                eventIdStr, // RequestType represents the EventID
                statusCode,
                userInfo,
                message // Payload holds description / CommandLine details
        );
    }
}
