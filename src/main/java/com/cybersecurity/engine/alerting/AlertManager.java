package com.cybersecurity.engine.alerting;

import com.cybersecurity.engine.model.Alert;
import com.cybersecurity.engine.model.Severity;
import com.cybersecurity.engine.model.ThreatCategory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;

/**
 * Thread-safe Alert Manager.
 * Utilizes a PriorityBlockingQueue to manage alerts, ensuring critical and high-risk alerts
 * are processed and displayed first.
 */
// Concept: Class
public class AlertManager {
    // Concept: Encapsulation (Private fields with controlled public accessors)
    // Thread-safe Priority Queue
    private final PriorityBlockingQueue<Alert> alertQueue = new PriorityBlockingQueue<>();
    // History list to keep track of all triggered alerts for report generation
    private final List<Alert> alertHistory = new ArrayList<>();

    // Counters for statistics
    private final Map<ThreatCategory, Integer> categoryCounters = new ConcurrentHashMap<>();
    private final Map<Severity, Integer> severityCounters = new ConcurrentHashMap<>();

    // Concept: Constructor (Initializes queue + counters)
    public AlertManager() {
        clearCounters();
    }

    /**
     * Adds an alert to the queue and increments corresponding analytics counters.
     *
     * @param alert The generated Alert.
     */
    // Concept: Methods
    public synchronized void addAlert(Alert alert) {
        if (alert == null) {
            return;
        }
        alertQueue.add(alert);
        alertHistory.add(alert);

        // Update statistics
        categoryCounters.put(alert.getCategory(), categoryCounters.getOrDefault(alert.getCategory(), 0) + 1);
        severityCounters.put(alert.getSeverity(), severityCounters.getOrDefault(alert.getSeverity(), 0) + 1);
    }

    /**
     * Pulls the highest priority alert from the queue.
     *
     * @return The highest priority Alert, or null if empty.
     */
    // Concept: Methods
    public Alert pollAlert() {
        return alertQueue.poll();
    }

    /**
     * Gets a copy of all alerts triggered in this session.
     */
    public synchronized List<Alert> getAlertHistory() {
        return new ArrayList<>(alertHistory);
    }

    /**
     * Retrieves all pending alerts currently in the queue, sorted by priority.
     */
    public synchronized List<Alert> getPendingAlertsSorted() {
        List<Alert> sortedList = new ArrayList<>();
        PriorityBlockingQueue<Alert> tempQueue = new PriorityBlockingQueue<>(alertQueue);
        while (!tempQueue.isEmpty()) {
            sortedList.add(tempQueue.poll());
        }
        return sortedList;
    }

    public int getQueueSize() {
        return alertQueue.size();
    }

    public int getHistorySize() {
        return alertHistory.size();
    }

    public Map<ThreatCategory, Integer> getCategoryStats() {
        return new ConcurrentHashMap<>(categoryCounters);
    }

    public Map<Severity, Integer> getSeverityStats() {
        return new ConcurrentHashMap<>(severityCounters);
    }

    private void clearCounters() {
        for (ThreatCategory cat : ThreatCategory.values()) {
            categoryCounters.put(cat, 0);
        }
        for (Severity sev : Severity.values()) {
            severityCounters.put(sev, 0);
        }
    }

    /**
     * Resets the manager.
     */
    public synchronized void clear() {
        alertQueue.clear();
        alertHistory.clear();
        clearCounters();
    }
}
