package com.cybersecurity.engine.parser;

/**
 * Factory class for instantiation of LogParser implementations.
 * Follows the Factory Design Pattern.
 */
public class LogParserFactory {
    /**
     * Factory method returning the appropriate parser for a given log type.
     *
     * @param logType The format type of log (APACHE, SYSLOG, WINDOWS).
     * @return An instance of LogParser.
     */
    public static LogParser getParser(String logType) {
        if (logType == null) {
            throw new IllegalArgumentException("Log type cannot be null");
        }
        return switch (logType.toUpperCase()) {
            case "APACHE" -> new ApacheLogParser();
            case "SYSLOG" -> new SyslogParser();
            case "WINDOWS" -> new WindowsEventLogParser();
            default -> throw new IllegalArgumentException("Unsupported log type: " + logType);
        };
    }
}
