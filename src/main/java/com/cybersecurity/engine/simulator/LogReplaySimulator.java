package com.cybersecurity.engine.simulator;

import com.cybersecurity.engine.alerting.AlertManager;
import com.cybersecurity.engine.detection.ThreatDetectorOrchestrator;
import com.cybersecurity.engine.model.Alert;
import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.parser.LogParser;
import com.cybersecurity.engine.parser.LogParserFactory;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Real-Time Log Replay Simulator.
 * Runs in a background thread to replay security logs line-by-line and simulate live monitoring.
 * Follows the Observer Pattern to notify UI layers of parsed logs and triggered alerts.
 */
// Concept: Class
public class LogReplaySimulator {
    private final String logResourcePath;
    private final String logType;
    private final ThreatDetectorOrchestrator orchestrator;
    private final AlertManager alertManager;
    private final List<LogSimulationListener> listeners = new CopyOnWriteArrayList<>();

    private final AtomicBoolean running = new AtomicBoolean(false);
    private int delayMs = 250; // Delay between log lines in milliseconds
    private Thread simulationThread;

    public interface LogSimulationListener {
        void onLogParsed(LogEntry entry);
        void onAlertTriggered(Alert alert);
        void onSimulationComplete();
    }

    // Concept: Constructor
    public LogReplaySimulator(String logResourcePath, String logType, 
                              ThreatDetectorOrchestrator orchestrator, AlertManager alertManager) {
        this.logResourcePath = logResourcePath;
        this.logType = logType;
        this.orchestrator = orchestrator;
        this.alertManager = alertManager;
    }

    public void addListener(LogSimulationListener listener) {
        listeners.add(listener);
    }

    public void removeListener(LogSimulationListener listener) {
        listeners.remove(listener);
    }

    public void setDelayMs(int delayMs) {
        this.delayMs = delayMs;
    }

    public int getDelayMs() {
        return delayMs;
    }

    public boolean isRunning() {
        return running.get();
    }

    /**
     * Starts the replay simulation in a background thread.
     */
    // Concept: Methods
    public synchronized void start() {
        if (running.get()) {
            return;
        }
        running.set(true);

        simulationThread = new Thread(this::runReplay, "LogReplayThread");
        simulationThread.start();
    }

    /**
     * Stops the simulation.
     */
    // Concept: Methods
    public synchronized void stop() {
        if (!running.get()) {
            return;
        }
        running.set(false);
        if (simulationThread != null) {
            simulationThread.interrupt();
        }
    }

    /**
     * Replays the log file.
     */
    private void runReplay() {
        LogParser parser = LogParserFactory.getParser(logType);
        
        try (InputStream is = getClass().getResourceAsStream(logResourcePath)) {
            if (is == null) {
                System.err.println("Simulator error: Resource " + logResourcePath + " not found.");
                running.set(false);
                notifySimulationComplete();
                return;
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                String line;
                // Topic: Loops
                while (running.get() && (line = reader.readLine()) != null) {
                    if (line.trim().isEmpty() || line.startsWith("#")) {
                        continue;
                    }

                    // Topic: Error Handling
                    try {
                        // Parse log line
                        // Concept: Object (Instantiation of LogEntry via parser.parse)
                        LogEntry entry = parser.parse(line);
                        notifyLogParsed(entry);

                        // Analyze for threats
                        Alert alert = orchestrator.analyze(entry);
                        if (alert != null) {
                            alertManager.addAlert(alert);
                            notifyAlertTriggered(alert);
                        }

                    } catch (Exception e) {
                        // Suppress line-level errors to continue replaying other lines
                    }

                    // Simulate delay
                    try {
                        Thread.sleep(delayMs);
                    } catch (InterruptedException e) {
                        // Allow interrupt to stop simulation cleanly
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Simulator error: " + e.getMessage());
        } finally {
            running.set(false);
            notifySimulationComplete();
        }
    }

    // Listener Notifications
    private void notifyLogParsed(LogEntry entry) {
        // Topic: Loops
        for (LogSimulationListener l : listeners) {
            l.onLogParsed(entry);
        }
    }

    private void notifyAlertTriggered(Alert alert) {
        // Topic: Loops
        for (LogSimulationListener l : listeners) {
            l.onAlertTriggered(alert);
        }
    }

    private void notifySimulationComplete() {
        // Topic: Loops
        for (LogSimulationListener l : listeners) {
            l.onSimulationComplete();
        }
    }
}
