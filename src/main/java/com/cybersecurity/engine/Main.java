package com.cybersecurity.engine;

import com.cybersecurity.engine.alerting.AlertManager;
import com.cybersecurity.engine.simulator.LogReplaySimulator;
import com.cybersecurity.engine.detection.ThreatDetectorOrchestrator;
import com.cybersecurity.engine.model.Alert;
import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.model.Severity;
import com.cybersecurity.engine.model.ThreatCategory;
import com.cybersecurity.engine.report.IncidentReportGenerator;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

/**
 * Main application entrypoint.
 * Hosts the interactive ANSI terminal console dashboard, statistics visualizations,
 * and handles live log replay simulation.
 */
// Concept: Class
public class Main {
    // ANSI Colors
    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";
    private static final String RED = "\u001B[31m";
    private static final String GREEN = "\u001B[32m";
    private static final String YELLOW = "\u001B[33m";
    private static final String BLUE = "\u001B[34m";
    private static final String PURPLE = "\u001B[35m";
    private static final String CYAN = "\u001B[36m";
    private static final String BG_RED = "\u001B[41m";

    private final ThreatDetectorOrchestrator orchestrator = new ThreatDetectorOrchestrator();
    private final AlertManager alertManager = new AlertManager();
    private final Scanner scanner = new Scanner(System.in);

    // Current simulator settings
    private String selectedLogPath = "/sample_logs/apache.log";
    private String selectedLogType = "APACHE";
    private LogReplaySimulator currentSimulator = null;
    private int customDelayMs = 200;

    private com.cybersecurity.engine.web.WebServer webServer = null;

    public static void main(String[] args) {
        if (args.length > 0 && ("--web".equalsIgnoreCase(args[0]) || "--server".equalsIgnoreCase(args[0]))) {
            com.cybersecurity.engine.web.WebServerLauncher.main(args);
            return;
        }
        Main app = new Main();
        app.run();
    }

    private void run() {
        printBanner();

        boolean exit = false;
        // Topic: Loops (interactive shell control loop)
        while (!exit) {
            printMainMenu();
            // Topic: Secure Input (menu input sanitization)
            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1" -> configureSimulation();
                case "2" -> runLiveSimulationMode();
                case "3" -> configureThresholds();
                case "4" -> manageThreatIntel();
                case "5" -> displayAlertDashboard();
                case "6" -> searchAlerts();
                case "7" -> clearAlerts();
                case "8" -> exportReport();
                case "9" -> {
                    stopActiveSimulation();
                    if (webServer != null) {
                        webServer.stop();
                    }
                    System.out.println(CYAN + "\nShutting down ATIE Engine. Goodbye!" + RESET);
                    exit = true;
                }
                case "10" -> launchWebDashboard();
                default -> System.out.println(RED + "Invalid choice! Please select 1-10." + RESET);
            }
        }
    }

    private void launchWebDashboard() {
        if (webServer == null) {
            try {
                webServer = new com.cybersecurity.engine.web.WebServer(8080, orchestrator, alertManager);
                webServer.start();
                System.out.println(GREEN + BOLD + ">>> Web Dashboard running at: http://localhost:8080/" + RESET);
                try {
                    if (java.awt.Desktop.isDesktopSupported() && java.awt.Desktop.getDesktop().isSupported(java.awt.Desktop.Action.BROWSE)) {
                        java.awt.Desktop.getDesktop().browse(new java.net.URI("http://localhost:8080/"));
                    }
                } catch (Exception ignored) {}
            } catch (Exception e) {
                System.out.println(RED + "Failed to launch Web Dashboard: " + e.getMessage() + RESET);
            }
        } else {
            System.out.println(GREEN + "Web Dashboard is already running at http://localhost:8080/" + RESET);
        }
    }

    private void printBanner() {
        System.out.println(CYAN + BOLD);
        System.out.println("╔══════════════════════════════════════════════════════════════════════╗");
        System.out.println("║         ADAPTIVE CYBERSECURITY THREAT INTELLIGENCE ENGINE            ║");
        System.out.println("║          Enterprise Security Information & Event Management          ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════╝" + RESET);
        System.out.println("Initializing detection engines... " + GREEN + "OK" + RESET);
        System.out.println("Loading IP reputation databases... " + GREEN + "OK (" + orchestrator.getThreatIntelEngine().getBlacklistSize() + " IPs)" + RESET);
        System.out.println("Compiling signature indices... " + GREEN + "OK" + RESET);
    }

    private void printMainMenu() {
        System.out.println("\n" + BOLD + "--- MAIN DASHBOARD CONTROL MENU ---" + RESET);
        System.out.println(CYAN + "1. " + RESET + "Configure Log Source [Current: " + BOLD + selectedLogType + RESET + " (" + selectedLogPath + ")]");
        System.out.println(CYAN + "2. " + RESET + "Launch Live Replay Monitoring Console");
        System.out.println(CYAN + "3. " + RESET + "Configure Detection Thresholds (Sliding Window / Z-Score)");
        System.out.println(CYAN + "4. " + RESET + "Manage Threat Intelligence (IP Blacklist)");
        System.out.println(CYAN + "5. " + RESET + "View Threat Analytics Dashboard (Sorted Alerts & Graphs)");
        System.out.println(CYAN + "6. " + RESET + "Search Active Alerts History (Search)");
        System.out.println(CYAN + "7. " + RESET + "Clear Alert History & Queue (Delete)");
        System.out.println(CYAN + "8. " + RESET + "Export Incident Investigation Report (Markdown)");
        System.out.println(CYAN + "9. " + RESET + "Exit Application");
        System.out.println(PURPLE + BOLD + "10." + RESET + " " + BOLD + "Launch Web Operations Dashboard (http://localhost:8080)" + RESET);
        System.out.print("\nSelect Option (1-10): ");
    }

    private void configureSimulation() {
        System.out.println("\n" + BOLD + "--- SELECT LOG DATASET SOURCE ---" + RESET);
        System.out.println("1. Apache Access Web Logs (Web Attacks: SQLi, XSS, Directory Traversal)");
        System.out.println("2. Linux Syslogs (Authentication failures, process audits)");
        System.out.println("3. Windows Security Event Logs (Active Directory logons, PowerShell command injections)");
        System.out.print("Select Dataset (1-3): ");
        String choice = scanner.nextLine().trim();
        switch (choice) {
            case "1" -> {
                selectedLogPath = "/sample_logs/apache.log";
                selectedLogType = "APACHE";
            }
            case "2" -> {
                selectedLogPath = "/sample_logs/syslog.log";
                selectedLogType = "SYSLOG";
            }
            case "3" -> {
                selectedLogPath = "/sample_logs/windows_events.csv";
                selectedLogType = "WINDOWS";
            }
            default -> {
                System.out.println(RED + "Invalid choice, keeping previous settings." + RESET);
                return;
            }
        }

        System.out.print("Enter replay delay in milliseconds (default: 200ms): ");
        String delayInput = scanner.nextLine().trim();
        if (!delayInput.isEmpty()) {
            try {
                customDelayMs = Integer.parseInt(delayInput);
                if (customDelayMs <= 0) customDelayMs = 200;
            } catch (NumberFormatException e) {
                System.out.println(RED + "Invalid number format. Using default 200ms." + RESET);
            }
        }

        System.out.println(GREEN + "Configuration updated successfully!" + RESET);
    }

    private void runLiveSimulationMode() {
        stopActiveSimulation();

        System.out.println("\n" + BOLD + "--- LIVE REPLAY MONITORING MODE ACTIVE ---" + RESET);
        System.out.println("Replaying " + BOLD + selectedLogType + RESET + " from resources path: " + selectedLogPath);
        System.out.println("Playback speed: " + customDelayMs + "ms per line. Press " + BOLD + "ENTER" + RESET + " to stop monitoring and return to menu.\n");

        currentSimulator = new LogReplaySimulator(selectedLogPath, selectedLogType, orchestrator, alertManager);
        currentSimulator.setDelayMs(customDelayMs);

        currentSimulator.addListener(new LogReplaySimulator.LogSimulationListener() {
            @Override
            public void onLogParsed(LogEntry entry) {
                System.out.printf("%s[PARSED LOG]%s IP:%-15s | User:%-10s | Payload: %s\n",
                        GREEN, RESET, entry.getIpAddress(), entry.getUserInfo(),
                        entry.getPayload().length() > 70 ? entry.getPayload().substring(0, 67) + "..." : entry.getPayload());
            }

            @Override
            public void onAlertTriggered(Alert alert) {
                // Beep sound on Critical alerts
                if (alert.getSeverity() == Severity.CRITICAL) {
                    System.out.print("\u0007"); // ASCII bell
                }
                String color = switch (alert.getSeverity()) {
                    case LOW -> YELLOW;
                    case MEDIUM -> PURPLE;
                    case HIGH -> RED;
                    case CRITICAL -> BOLD + BG_RED + RED;
                };
                System.out.printf("%s!!! ALERT: [%s] %s | IP: %s | Severity: %s | Risk: %.1f | msg: %s !!!%s\n",
                        color, alert.getCategory().getDisplayName(), alert.getSeverity(),
                        alert.getSourceIp(), alert.getSeverity(), alert.getRiskScore(),
                        alert.getDescription(), RESET);
            }

            @Override
            public void onSimulationComplete() {
                System.out.println(CYAN + "\n--- Log file playback simulation completed ---" + RESET);
            }
        });

        // Clear previous state for a clean test run
        orchestrator.getzScoreAnalyzer().reset();
        orchestrator.getSlidingWindowDetector().clear();

        currentSimulator.start();

        // Wait for user to hit enter to stop
        scanner.nextLine();
        stopActiveSimulation();
        System.out.println(GREEN + "Returned to Main Dashboard." + RESET);
    }

    private void stopActiveSimulation() {
        if (currentSimulator != null && currentSimulator.isRunning()) {
            currentSimulator.stop();
            System.out.println("Replay simulator thread terminated.");
        }
    }

    private void configureThresholds() {
        System.out.println("\n" + BOLD + "--- CONFIGURE DETECTION ALGORITHMS ---" + RESET);
        System.out.println("1. Adjust Brute Force Sliding Window Thresholds");
        System.out.println("2. Adjust Z-Score Anomaly Sensitivity");
        System.out.print("Select Option (1-2): ");
        String option = scanner.nextLine().trim();

        if ("1".equals(option)) {
            int win = orchestrator.getSlidingWindowDetector().getTimeWindowSeconds();
            int thresh = orchestrator.getSlidingWindowDetector().getFailureThreshold();
            System.out.printf("Current Window: %d seconds, Current Threshold: %d failures\n", win, thresh);
            
            try {
                System.out.print("Enter new time window in seconds (default: 60): ");
                String winInput = scanner.nextLine().trim();
                int newWin = winInput.isEmpty() ? 60 : Integer.parseInt(winInput);

                System.out.print("Enter new failure count threshold (default: 5): ");
                String threshInput = scanner.nextLine().trim();
                int newThresh = threshInput.isEmpty() ? 5 : Integer.parseInt(threshInput);

                orchestrator.getSlidingWindowDetector().setThresholds(newWin, newThresh);
                System.out.println(GREEN + "Brute force thresholds updated." + RESET);
            } catch (Exception e) {
                System.out.println(RED + "Invalid input format. Keeping default thresholds." + RESET);
            }
        } else if ("2".equals(option)) {
            double currentZ = orchestrator.getzScoreAnalyzer().getZScoreThreshold();
            System.out.printf("Current Z-Score sensitivity limit: %.2f standard deviations\n", currentZ);
            try {
                System.out.print("Enter new Z-Score threshold (e.g. 2.0 to 3.5, default: 2.5): ");
                String zInput = scanner.nextLine().trim();
                double newZ = zInput.isEmpty() ? 2.5 : Double.parseDouble(zInput);
                orchestrator.getzScoreAnalyzer().setZScoreThreshold(newZ);
                System.out.println(GREEN + "Z-Score anomaly sensitivity updated." + RESET);
            } catch (Exception e) {
                System.out.println(RED + "Invalid input format. Keeping default thresholds." + RESET);
            }
        } else {
            System.out.println(RED + "Invalid option." + RESET);
        }
    }

    private void manageThreatIntel() {
        System.out.println("\n" + BOLD + "--- THREAT INTELLIGENCE (IP REPUTATION) ---" + RESET);
        System.out.println("1. Check IP Reputation");
        System.out.println("2. Add IP to Threat Blacklist");
        System.out.println("3. View Blacklist Database Statistics");
        System.out.print("Select Option (1-3): ");
        String option = scanner.nextLine().trim();

        if ("1".equals(option)) {
            System.out.print("Enter IP Address to check: ");
            String ip = scanner.nextLine().trim();
            boolean blacklisted = orchestrator.getThreatIntelEngine().isBlacklisted(ip);
            if (blacklisted) {
                System.out.println(RED + "IP: " + ip + " IS BLACKLISTED (Known Threat Actor)" + RESET);
            } else {
                System.out.println(GREEN + "IP: " + ip + " IS CLEAN (No negative reports)" + RESET);
            }
        } else if ("2".equals(option)) {
            System.out.print("Enter IP Address to blacklist: ");
            String ip = scanner.nextLine().trim();
            orchestrator.getThreatIntelEngine().addIPToBlacklist(ip);
            System.out.println(GREEN + "IP " + ip + " successfully added to active blacklist database." + RESET);
        } else if ("3".equals(option)) {
            System.out.println("Current active blacklist count: " + BOLD + orchestrator.getThreatIntelEngine().getBlacklistSize() + " threat records" + RESET);
        } else {
            System.out.println(RED + "Invalid option." + RESET);
        }
    }

    private void displayAlertDashboard() {
        System.out.println("\n" + BOLD + "--- SECURITY THREAT ANALYTICS DASHBOARD ---" + RESET);

        int totalAlerts = alertManager.getHistorySize();
        System.out.println("Total Incidents Logged: " + BOLD + totalAlerts + RESET);

        if (totalAlerts == 0) {
            System.out.println(GREEN + "No threat alerts logged in active session." + RESET);
            return;
        }

        // Draw Severity Distribution Bar Chart
        Map<Severity, Integer> severityStats = alertManager.getSeverityStats();
        System.out.println("\n" + BOLD + "Severity Distribution Graph:" + RESET);
        // Topic: Loops
        for (Severity sev : Severity.values()) {
            int count = severityStats.getOrDefault(sev, 0);
            int percentage = totalAlerts > 0 ? (count * 100) / totalAlerts : 0;
            // Draw a solid text-based progress bar
            int bars = percentage / 5;
            String barStr = "█".repeat(bars) + "░".repeat(20 - bars);
            String color = switch (sev) {
                case LOW -> YELLOW;
                case MEDIUM -> PURPLE;
                case HIGH -> RED;
                case CRITICAL -> BOLD + RED;
            };
            System.out.printf("  %-10s [%s%s%s] %3d%% (%d alerts)\n", sev, color, barStr, RESET, percentage, count);
        }

        // Draw Threat Category distribution
        Map<ThreatCategory, Integer> categoryStats = alertManager.getCategoryStats();
        System.out.println("\n" + BOLD + "Threat Vector Classifications:" + RESET);
        // Topic: Loops
        for (Map.Entry<ThreatCategory, Integer> entry : categoryStats.entrySet()) {
            if (entry.getValue() > 0) {
                System.out.printf("  %-25s : %2d alerts\n", entry.getKey().getDisplayName(), entry.getValue());
            }
        }

        // Display top priority alerts
        System.out.println("\n" + BOLD + "Top Active Threat Alerts (Priority Queue Ordering):" + RESET);
        List<Alert> priorityAlerts = alertManager.getPendingAlertsSorted();
        int displayLimit = Math.min(10, priorityAlerts.size());
        // Topic: Loops
        for (int i = 0; i < displayLimit; i++) {
            Alert alert = priorityAlerts.get(i);
            String color = switch (alert.getSeverity()) {
                case LOW -> YELLOW;
                case MEDIUM -> PURPLE;
                case HIGH -> RED;
                case CRITICAL -> BOLD + RED;
            };
            System.out.printf("  [%d] %s[Severity: %s]%s Risk: %3.1f | IP: %-15s | Target: %-15s | %s\n",
                    i + 1, color, alert.getSeverity(), RESET, alert.getRiskScore(),
                    alert.getSourceIp(), alert.getAffectedSystem(), alert.getDescription());
        }
    }

    private void searchAlerts() {
        System.out.println("\n" + BOLD + "--- SEARCH ACTIVE ALERTS HISTORY ---" + RESET);
        List<Alert> alerts = alertManager.getAlertHistory();
        if (alerts.isEmpty()) {
            System.out.println(YELLOW + "No alerts logged in the active session to search." + RESET);
            return;
        }

        System.out.println("Search by: ");
        System.out.println("1. Attacking Source IP");
        System.out.println("2. Threat Category");
        System.out.println("3. Severity Level");
        System.out.print("Select choice (1-3): ");
        String choice = scanner.nextLine().trim();

        List<Alert> results = new ArrayList<>();
        switch (choice) {
            case "1" -> {
                System.out.print("Enter IP to search (e.g. 192.168.1.15): ");
                String ip = scanner.nextLine().trim();
                // Topic: Loops
                for (Alert a : alerts) {
                    if (a.getSourceIp().contains(ip)) {
                        results.add(a);
                    }
                }
            }
            case "2" -> {
                System.out.println("Select category:");
                // Topic: Loops
                for (ThreatCategory cat : ThreatCategory.values()) {
                    System.out.println("  " + cat.name() + " -> " + cat.getDisplayName());
                }
                System.out.print("Enter category name: ");
                String catName = scanner.nextLine().trim().toUpperCase();
                // Topic: Loops
                for (Alert a : alerts) {
                    if (a.getCategory().name().equals(catName)) {
                        results.add(a);
                    }
                }
            }
            case "3" -> {
                System.out.print("Enter severity level (LOW, MEDIUM, HIGH, CRITICAL): ");
                String sevName = scanner.nextLine().trim().toUpperCase();
                // Topic: Loops
                for (Alert a : alerts) {
                    if (a.getSeverity().name().equals(sevName)) {
                        results.add(a);
                    }
                }
            }
            default -> {
                System.out.println(RED + "Invalid choice." + RESET);
                return;
            }
        }

        System.out.println("\n" + BOLD + "Search Results (" + results.size() + " matches found):" + RESET);
        if (results.isEmpty()) {
            System.out.println(YELLOW + "No matching alerts found." + RESET);
        } else {
            // Sort by priority (severity and risk score)
            results.sort(null); // uses Alert.compareTo
            // Topic: Loops
            for (int i = 0; i < results.size(); i++) {
                Alert a = results.get(i);
                String color = switch (a.getSeverity()) {
                    case LOW -> YELLOW;
                    case MEDIUM -> PURPLE;
                    case HIGH -> RED;
                    case CRITICAL -> BOLD + RED;
                };
                System.out.printf("  [%d] %s[Severity: %s]%s Risk: %3.1f | IP: %-15s | %s\n",
                        i + 1, color, a.getSeverity(), RESET, a.getRiskScore(),
                        a.getSourceIp(), a.getDescription());
            }
        }
    }

    private void clearAlerts() {
        System.out.println("\n" + BOLD + "--- CLEAR ACTIVE ALERT HISTORY ---" + RESET);
        System.out.print("Are you sure you want to clear all active alerts and counters? (y/n): ");
        String confirm = scanner.nextLine().trim().toLowerCase();
        if ("y".equals(confirm) || "yes".equals(confirm)) {
            alertManager.clear();
            System.out.println(GREEN + "Alert queue, history, and statistics counters have been reset successfully." + RESET);
        } else {
            System.out.println(YELLOW + "Clear operation cancelled." + RESET);
        }
    }

    private void exportReport() {
        System.out.println("\n" + BOLD + "--- EXPORT SECURITY INVESTIGATION REPORT ---" + RESET);
        List<Alert> alerts = alertManager.getAlertHistory();
        if (alerts.isEmpty()) {
            System.out.println(YELLOW + "Warning: No alerts logged to export. Run live simulation mode first." + RESET);
            return;
        }

        String reportFileName = "incident_report.md";
        System.out.print("Enter output filename (default: incident_report.md): ");
        String inputName = scanner.nextLine().trim();
        if (!inputName.isEmpty()) {
            reportFileName = inputName;
        }

        // Topic: Error Handling
        try {
            IncidentReportGenerator.generateMarkdownReport(alerts, reportFileName);
            System.out.println(GREEN + "Report exported successfully to: " + BOLD + reportFileName + RESET);
        } catch (IOException e) {
            System.out.println(RED + "Failed to write report file: " + e.getMessage() + RESET);
        }
    }
}
