package com.cybersecurity.engine.parser;

import com.cybersecurity.engine.model.LogEntry;

/**
 * Interface defining the parsing contract for different log formats.
 */
// Concept: Abstraction (Hides format-specific parsing details from orchestrator and simulator)
public interface LogParser {
    /**
     * Parses a single raw log line into a structured LogEntry object.
     *
     * @param rawLogLine The raw line from the log file.
     * @return A structured LogEntry.
     * @throws Exception if parsing fails or log format is incorrect.
     */
    LogEntry parse(String rawLogLine) throws Exception;
}
