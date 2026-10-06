package com.cybersecurity.engine.detection;

import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.model.ThreatCategory;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Anomaly Detection Module using Z-Score Analysis.
 * Tracks log volume trends in time buckets and flags sudden traffic spikes or anomalies.
 */
public class ZScoreAnalyzer {
    private final List<Integer> baselineHistory = new ArrayList<>();
    private final int baselineLimit = 50; // Keep last 50 buckets as baseline
    private double zScoreThreshold = 2.5;

    // Bucket tracking variables
    private LocalDateTime currentBucketStart = null;
    private int currentBucketCount = 0;
    private final int bucketDurationSeconds = 5; // Group logs into 5-second windows

    public ZScoreAnalyzer() {}

    public ZScoreAnalyzer(double zScoreThreshold) {
        this.zScoreThreshold = zScoreThreshold;
    }

    public synchronized void setZScoreThreshold(double threshold) {
        this.zScoreThreshold = threshold;
    }

    public double getZScoreThreshold() {
        return zScoreThreshold;
    }

    public List<Integer> getBaselineHistory() {
        return new ArrayList<>(baselineHistory);
    }

    /**
     * Feeds a log entry into the Z-Score tracker.
     * Groups logs by timestamp into buckets and evaluates Z-Scores upon bucket boundary crossings.
     *
     * @param entry The LogEntry to analyze.
     * @return An AnomalyResult if a traffic spike/anomaly is detected, null otherwise.
     */
    public synchronized AnomalyResult analyze(LogEntry entry) {
        LocalDateTime logTime = entry.getTimestamp();

        if (currentBucketStart == null) {
            currentBucketStart = logTime;
            currentBucketCount = 1;
            return null;
        }

        long diff = ChronoUnit.SECONDS.between(currentBucketStart, logTime);

        if (diff < bucketDurationSeconds) {
            // Log falls into the current bucket
            currentBucketCount++;
            return null;
        } else {
            // Bucket boundary crossed! Evaluate the completed bucket count
            int finishedCount = currentBucketCount;
            LocalDateTime finishedBucketStart = currentBucketStart;

            // Reset for the new bucket
            currentBucketStart = logTime;
            currentBucketCount = 1;

            // Evaluate Z-Score for finishedCount
            AnomalyResult result = evaluateCount(finishedCount, finishedBucketStart);

            // Add finishedCount to baseline history
            baselineHistory.add(finishedCount);
            if (baselineHistory.size() > baselineLimit) {
                baselineHistory.remove(0);
            }

            return result;
        }
    }

    /**
     * Computes the mean, standard deviation, and Z-Score for the given count against the history.
     */
    private AnomalyResult evaluateCount(int count, LocalDateTime bucketTime) {
        // Need at least 5 baseline points to compute meaningful Z-Score
        if (baselineHistory.size() < 5) {
            return null;
        }

        // Calculate Mean
        double sum = 0;
        for (int c : baselineHistory) {
            sum += c;
        }
        double mean = sum / baselineHistory.size();

        // Calculate Standard Deviation
        double sqSum = 0;
        for (int c : baselineHistory) {
            sqSum += Math.pow(c - mean, 2);
        }
        double stdDev = Math.sqrt(sqSum / baselineHistory.size());

        // Handle case where standard deviation is zero (stable traffic)
        if (stdDev < 0.0001) {
            // If count is significantly higher than mean, flag anomaly
            if (count > mean + 5) {
                return new AnomalyResult(
                        ThreatCategory.TRAFFIC_ANOMALY,
                        String.format("Traffic Anomaly: Stable traffic (mean=%.1f, stddev=0) spiked to %d requests.", mean, count),
                        9.9
                );
            }
            return null;
        }

        // Calculate Z-Score
        double zScore = (count - mean) / stdDev;

        // Flag positive Z-Score spikes that exceed threshold
        if (zScore > zScoreThreshold) {
            return new AnomalyResult(
                    ThreatCategory.TRAFFIC_ANOMALY,
                    String.format("Traffic Spike Detected: Count of %d exceeded mean of %.1f by %.2f standard deviations (Z-Score = %.2f).",
                            count, mean, zScore, zScore),
                    zScore
            );
        }

        return null;
    }

    /**
     * Resets the analyzer.
     */
    public synchronized void reset() {
        baselineHistory.clear();
        currentBucketStart = null;
        currentBucketCount = 0;
    }

    public static class AnomalyResult {
        private final ThreatCategory category;
        private final String message;
        private final double zScore;

        public AnomalyResult(ThreatCategory category, String message, double zScore) {
            this.category = category;
            this.message = message;
            this.zScore = zScore;
        }

        public ThreatCategory getCategory() {
            return category;
        }

        public String getMessage() {
            return message;
        }

        public double getZScore() {
            return zScore;
        }
    }
}
