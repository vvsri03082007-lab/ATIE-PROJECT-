package com.cybersecurity.engine.parser;

import com.cybersecurity.engine.model.LogEntry;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Log Parser for Apache Web Server logs (Combined and Common Log Formats).
 */
// Concept: Inheritance (Implementing the LogParser interface)
public class ApacheLogParser implements LogParser {
    // Regex matching standard Apache Combined Log format
    private static final Pattern APACHE_PATTERN = Pattern.compile(
            "^(\\S+) (\\S+) (\\S+) \\[([^\\]]+)\\] \"([^\"]*)\" (\\d+) (\\S+)(?: \"([^\"]*)\" \"([^\"]*)\")?$"
    );

    private static final DateTimeFormatter DATE_FORMATTER =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    // Concept: Polymorphism (Overriding the parse contract to implement specific Apache log parsing)
    @Override
    public LogEntry parse(String rawLogLine) throws Exception {
        if (rawLogLine == null || rawLogLine.trim().isEmpty()) {
            throw new IllegalArgumentException("Log line is empty");
        }

        Matcher matcher = APACHE_PATTERN.matcher(rawLogLine.trim());
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Log line does not match Apache Combined format");
        }

        String ipAddress = matcher.group(1);
        String rfcIdentity = matcher.group(2);
        String userId = matcher.group(3);
        String timeStr = matcher.group(4);
        String requestStr = matcher.group(5);
        String statusStr = matcher.group(6);
        String bytesStr = matcher.group(7);

        // Parse timestamp
        LocalDateTime timestamp;
        try {
            ZonedDateTime zdt = ZonedDateTime.parse(timeStr, DATE_FORMATTER);
            timestamp = zdt.toLocalDateTime();
        } catch (Exception e) {
            timestamp = LocalDateTime.now(); // Fallback
        }

        // Parse HTTP Request (e.g. "GET /index.html HTTP/1.1")
        String requestType = "UNKNOWN";
        String payload = requestStr;
        if (requestStr != null && !requestStr.isEmpty()) {
            String[] parts = requestStr.split("\\s+");
            if (parts.length > 0) {
                requestType = parts[0]; // e.g. GET
            }
            if (parts.length > 1) {
                payload = parts[1]; // e.g. /index.html
                try {
                    payload = java.net.URLDecoder.decode(payload.replace("+", " "), java.nio.charset.StandardCharsets.UTF_8);
                } catch (Exception ignored) {}
            }
        }

        // Parse HTTP Status
        int statusCode = 200;
        try {
            statusCode = Integer.parseInt(statusStr);
        } catch (NumberFormatException ignored) {}

        // User info is either the authenticated user ID or fallback
        String userInfo = "-".equals(userId) ? "ANONYMOUS" : userId;

        // Concept: Object (Instantiation of a new LogEntry per parsed log line)
        return new LogEntry(
                rawLogLine,
                "APACHE",
                timestamp,
                ipAddress,
                requestType,
                statusCode,
                userInfo,
                payload
        );
    }
}
