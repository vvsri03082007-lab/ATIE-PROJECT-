package com.cybersecurity.engine.model;

import java.time.LocalDateTime;

/**
 * Model class representing a parsed log record.
 * Holds clean fields extracted from raw log strings.
 */
// Concept: Class
public class LogEntry {
    // Concept: Encapsulation
    private final String rawLog;
    private final String logType; // "APACHE", "SYSLOG", "WINDOWS"
    private final LocalDateTime timestamp;
    private final String ipAddress;
    private final String requestType; // HTTP Method (e.g. GET/POST), Service Name (sshd), or EventID
    private final int statusCode; // HTTP Status Code, Syslog PID, or Windows Event Success/Failure Flag
    private final String userInfo; // Authenticating username or system user
    private final String payload; // URL path/query, syslog details, or Windows command line arguments

    public LogEntry(String rawLog, String logType, LocalDateTime timestamp, String ipAddress,
                    String requestType, int statusCode, String userInfo, String payload) {
        this.rawLog = rawLog;
        this.logType = logType;
        this.timestamp = timestamp;
        this.ipAddress = ipAddress;
        this.requestType = requestType;
        this.statusCode = statusCode;
        this.userInfo = userInfo;
        this.payload = payload;
    }

    public String getRawLog() {
        return rawLog;
    }

    public String getLogType() {
        return logType;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getRequestType() {
        return requestType;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getUserInfo() {
        return userInfo;
    }

    public String getPayload() {
        return payload;
    }

    @Override
    public String toString() {
        return String.format("[%s] %s | IP: %s | User: %s | Req: %s | Code: %d | Payload: %s",
                logType, timestamp, ipAddress, userInfo, requestType, statusCode, payload);
    }
}
