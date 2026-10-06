package com.cybersecurity.engine.web;

import com.cybersecurity.engine.alerting.AlertManager;
import com.cybersecurity.engine.detection.ThreatDetectorOrchestrator;
import com.cybersecurity.engine.model.Alert;
import com.cybersecurity.engine.model.LogEntry;
import com.cybersecurity.engine.model.Severity;
import com.cybersecurity.engine.model.ThreatCategory;
import com.cybersecurity.engine.parser.LogParser;
import com.cybersecurity.engine.parser.LogParserFactory;
import com.cybersecurity.engine.simulator.LogReplaySimulator;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * High-performance, zero-dependency embedded HTTP server.
 * Serves the modern Cybersecurity Operations Center (SOC) dashboard and
 * provides real-time Server-Sent Events (SSE) telemetry and REST APIs.
 */
public class WebServer {
    private final int port;
    private HttpServer server;
    private final ThreatDetectorOrchestrator orchestrator;
    private final AlertManager alertManager;
    private final ExecutorService executor = Executors.newCachedThreadPool();

    private LogReplaySimulator currentSimulator = null;
    private String currentLogType = "APACHE";
    private int currentDelayMs = 200;
    private final AtomicInteger logsIngestedCount = new AtomicInteger(0);

    // Connected SSE clients for real-time telemetry streaming
    private final Set<HttpExchange> sseClients = ConcurrentHashMap.newKeySet();

    public WebServer(int port) {
        this(port, new ThreatDetectorOrchestrator(), new AlertManager());
    }

    public WebServer(int port, ThreatDetectorOrchestrator orchestrator, AlertManager alertManager) {
        this.port = port;
        this.orchestrator = orchestrator;
        this.alertManager = alertManager;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(executor);

        // Static files handler
        server.createContext("/", new StaticFileHandler());

        // REST API Endpoints
        server.createContext("/api/status", this::handleStatus);
        server.createContext("/api/alerts", this::handleAlerts);
        server.createContext("/api/simulation/start", this::handleStartSimulation);
        server.createContext("/api/simulation/stop", this::handleStopSimulation);
        server.createContext("/api/simulation/stream", this::handleSseStream);
        server.createContext("/api/intel/blacklist", this::handleBlacklist);
        server.createContext("/api/thresholds", this::handleThresholds);
        server.createContext("/api/alerts/clear", this::handleClearAlerts);
        server.createContext("/api/report/markdown", this::handleReport);
        server.createContext("/api/custom-log/analyze", this::handleCustomLogAnalyze);

        server.start();
        System.out.println("\u001B[32m[+] ATIE Web Operations Center initialized.\u001B[0m");
        System.out.println("\u001B[36m[+] Dashboard URL: http://localhost:" + port + "/\u001B[0m");
    }

    public void stop() {
        if (currentSimulator != null && currentSimulator.isRunning()) {
            currentSimulator.stop();
        }
        for (HttpExchange client : sseClients) {
            try {
                client.close();
            } catch (Exception ignored) {}
        }
        sseClients.clear();
        if (server != null) {
            server.stop(1);
        }
        executor.shutdownNow();
    }

    public int getPort() {
        return port;
    }

    // --- SSE Streaming Methods ---

    private void handleSseStream(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/event-stream");
        headers.set("Cache-Control", "no-cache, no-transform");
        headers.set("Connection", "keep-alive");
        headers.set("Access-Control-Allow-Origin", "*");

        exchange.sendResponseHeaders(200, 0); // Chunked transfer
        OutputStream os = exchange.getResponseBody();
        os.write(": connected\n\n".getBytes(StandardCharsets.UTF_8));
        os.flush();

        sseClients.add(exchange);
    }

    public synchronized void broadcastEvent(String eventType, String jsonData) {
        if (sseClients.isEmpty()) return;

        String ssePayload = "event: " + eventType + "\ndata: " + jsonData + "\n\n";
        byte[] bytes = ssePayload.getBytes(StandardCharsets.UTF_8);

        Iterator<HttpExchange> iterator = sseClients.iterator();
        while (iterator.hasNext()) {
            HttpExchange client = iterator.next();
            try {
                OutputStream os = client.getResponseBody();
                os.write(bytes);
                os.flush();
            } catch (Exception e) {
                try {
                    client.close();
                } catch (Exception ignored) {}
                iterator.remove();
            }
        }
    }

    // --- REST Handlers ---

    private void handleStatus(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        Map<Severity, Integer> sevStats = alertManager.getSeverityStats();
        Map<ThreatCategory, Integer> catStats = alertManager.getCategoryStats();

        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"status\":\"ONLINE\",");
        json.append("\"logType\":\"").append(escapeJson(currentLogType)).append("\",");
        json.append("\"isSimulating\":").append(currentSimulator != null && currentSimulator.isRunning()).append(",");
        json.append("\"delayMs\":").append(currentDelayMs).append(",");
        json.append("\"totalLogsIngested\":").append(logsIngestedCount.get()).append(",");
        json.append("\"totalAlerts\":").append(alertManager.getHistorySize()).append(",");
        json.append("\"queueSize\":").append(alertManager.getQueueSize()).append(",");
        json.append("\"blacklistCount\":").append(orchestrator.getThreatIntelEngine().getBlacklistSize()).append(",");

        // Thresholds
        json.append("\"thresholds\":{");
        json.append("\"slidingWindowSeconds\":").append(orchestrator.getSlidingWindowDetector().getTimeWindowSeconds()).append(",");
        json.append("\"failureThreshold\":").append(orchestrator.getSlidingWindowDetector().getFailureThreshold()).append(",");
        json.append("\"zScore\":").append(orchestrator.getzScoreAnalyzer().getZScoreThreshold());
        json.append("},");

        // Severity stats
        json.append("\"severityStats\":{");
        boolean first = true;
        for (Severity s : Severity.values()) {
            if (!first) json.append(",");
            json.append("\"").append(s.name()).append("\":").append(sevStats.getOrDefault(s, 0));
            first = false;
        }
        json.append("},");

        // Category stats
        json.append("\"categoryStats\":{");
        first = true;
        for (ThreatCategory c : ThreatCategory.values()) {
            if (!first) json.append(",");
            json.append("\"").append(c.name()).append("\":").append(catStats.getOrDefault(c, 0));
            first = false;
        }
        json.append("}");

        json.append("}");

        sendResponse(exchange, 200, "application/json", json.toString());
    }

    private void handleAlerts(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        String query = exchange.getRequestURI().getQuery();
        String search = null;
        if (query != null && query.contains("q=")) {
            for (String param : query.split("&")) {
                if (param.startsWith("q=")) {
                    search = URLDecoder.decode(param.substring(2), StandardCharsets.UTF_8).toLowerCase();
                    break;
                }
            }
        }

        List<Alert> allAlerts = alertManager.getAlertHistory();
        // Sort by timestamp descending
        List<Alert> filtered = new ArrayList<>();
        for (int i = allAlerts.size() - 1; i >= 0; i--) {
            Alert a = allAlerts.get(i);
            if (search != null && !search.isEmpty()) {
                boolean match = a.getSourceIp().toLowerCase().contains(search)
                        || a.getCategory().name().toLowerCase().contains(search)
                        || a.getSeverity().name().toLowerCase().contains(search)
                        || a.getDescription().toLowerCase().contains(search)
                        || a.getAffectedSystem().toLowerCase().contains(search);
                if (!match) continue;
            }
            filtered.add(a);
        }

        StringBuilder json = new StringBuilder();
        json.append("{\"alerts\":[");
        for (int i = 0; i < filtered.size(); i++) {
            if (i > 0) json.append(",");
            json.append(alertToJson(filtered.get(i)));
        }
        json.append("]}");

        sendResponse(exchange, 200, "application/json", json.toString());
    }

    private void handleStartSimulation(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        String body = readRequestBody(exchange);
        String logType = parseJsonField(body, "logType", "APACHE").toUpperCase();
        int delay = parseIntField(body, "delayMs", 200);

        String resourcePath = switch (logType) {
            case "SYSLOG" -> "/sample_logs/syslog.log";
            case "WINDOWS" -> "/sample_logs/windows_events.csv";
            default -> "/sample_logs/apache.log";
        };

        if (currentSimulator != null && currentSimulator.isRunning()) {
            currentSimulator.stop();
        }

        this.currentLogType = logType;
        this.currentDelayMs = Math.max(20, Math.min(2000, delay));

        currentSimulator = new LogReplaySimulator(resourcePath, logType, orchestrator, alertManager);
        currentSimulator.setDelayMs(currentDelayMs);

        currentSimulator.addListener(new LogReplaySimulator.LogSimulationListener() {
            @Override
            public void onLogParsed(LogEntry entry) {
                logsIngestedCount.incrementAndGet();
                broadcastEvent("log", logEntryToJson(entry));
            }

            @Override
            public void onAlertTriggered(Alert alert) {
                broadcastEvent("alert", alertToJson(alert));
            }

            @Override
            public void onSimulationComplete() {
                broadcastEvent("complete", "{\"message\":\"Log replay simulation completed\",\"totalLogs\":" + logsIngestedCount.get() + "}");
            }
        });

        currentSimulator.start();

        sendResponse(exchange, 200, "application/json",
                "{\"success\":true,\"message\":\"Simulation started for " + logType + "\",\"delayMs\":" + currentDelayMs + "}");
    }

    private void handleStopSimulation(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        if (currentSimulator != null) {
            currentSimulator.stop();
        }
        broadcastEvent("stopped", "{\"message\":\"Simulation stopped by user\"}");
        sendResponse(exchange, 200, "application/json", "{\"success\":true,\"message\":\"Simulation halted\"}");
    }

    private void handleBlacklist(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();

        if ("GET".equalsIgnoreCase(method)) {
            Set<String> ips = orchestrator.getThreatIntelEngine().getBlacklistedIPs();
            StringBuilder json = new StringBuilder("{\"blacklist\":[");
            int i = 0;
            for (String ip : ips) {
                if (i > 0) json.append(",");
                json.append("\"").append(escapeJson(ip)).append("\"");
                i++;
            }
            json.append("]}");
            sendResponse(exchange, 200, "application/json", json.toString());

        } else if ("POST".equalsIgnoreCase(method)) {
            String body = readRequestBody(exchange);
            String ip = parseJsonField(body, "ip", "").trim();
            if (ip.isEmpty()) {
                sendResponse(exchange, 400, "application/json", "{\"error\":\"Invalid or empty IP address\"}");
                return;
            }
            orchestrator.getThreatIntelEngine().addIPToBlacklist(ip);
            sendResponse(exchange, 200, "application/json", "{\"success\":true,\"message\":\"IP " + escapeJson(ip) + " added to blacklist\"}");

        } else if ("DELETE".equalsIgnoreCase(method)) {
            String query = exchange.getRequestURI().getQuery();
            String ip = null;
            if (query != null && query.contains("ip=")) {
                for (String param : query.split("&")) {
                    if (param.startsWith("ip=")) {
                        ip = URLDecoder.decode(param.substring(3), StandardCharsets.UTF_8).trim();
                        break;
                    }
                }
            }
            if (ip == null || ip.isEmpty()) {
                String body = readRequestBody(exchange);
                ip = parseJsonField(body, "ip", "").trim();
            }

            if (ip.isEmpty()) {
                sendResponse(exchange, 400, "application/json", "{\"error\":\"Missing IP parameter\"}");
                return;
            }

            boolean removed = orchestrator.getThreatIntelEngine().removeIPFromBlacklist(ip);
            sendResponse(exchange, 200, "application/json", "{\"success\":" + removed + ",\"ip\":\"" + escapeJson(ip) + "\"}");
        } else {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
        }
    }

    private void handleThresholds(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        String body = readRequestBody(exchange);
        int window = parseIntField(body, "slidingWindowSeconds", orchestrator.getSlidingWindowDetector().getTimeWindowSeconds());
        int failureThresh = parseIntField(body, "failureThreshold", orchestrator.getSlidingWindowDetector().getFailureThreshold());
        double zScore = parseDoubleField(body, "zScore", orchestrator.getzScoreAnalyzer().getZScoreThreshold());

        orchestrator.getSlidingWindowDetector().setThresholds(window, failureThresh);
        orchestrator.getzScoreAnalyzer().setZScoreThreshold(zScore);

        sendResponse(exchange, 200, "application/json",
                "{\"success\":true,\"slidingWindowSeconds\":" + window + ",\"failureThreshold\":" + failureThresh + ",\"zScore\":" + zScore + "}");
    }

    private void handleClearAlerts(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        alertManager.clear();
        logsIngestedCount.set(0);
        broadcastEvent("cleared", "{\"message\":\"Alerts cleared\"}");
        sendResponse(exchange, 200, "application/json", "{\"success\":true,\"message\":\"Alerts and counters cleared\"}");
    }

    private void handleReport(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        List<Alert> history = alertManager.getAlertHistory();
        String tempReportPath = "target/web_incident_report.md";
        com.cybersecurity.engine.report.IncidentReportGenerator.generateMarkdownReport(history, tempReportPath);

        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(tempReportPath, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (Exception e) {
            content.append("# Error generating report\n").append(e.getMessage());
        }

        sendResponse(exchange, 200, "text/markdown; charset=UTF-8", content.toString());
    }

    private void handleCustomLogAnalyze(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "application/json", "{\"error\":\"Method Not Allowed\"}");
            return;
        }

        String body = readRequestBody(exchange);
        String logType = parseJsonField(body, "logType", "APACHE").toUpperCase();
        String rawLog = parseJsonField(body, "rawLog", "");

        if (rawLog.isEmpty()) {
            sendResponse(exchange, 400, "application/json", "{\"error\":\"Empty log input\"}");
            return;
        }

        LogParser parser = LogParserFactory.getParser(logType);
        LogEntry entry;
        try {
            entry = parser.parse(rawLog);
        } catch (Exception e) {
            sendResponse(exchange, 400, "application/json", "{\"error\":\"Failed to parse log entry: " + escapeJson(e.getMessage()) + "\"}");
            return;
        }

        logsIngestedCount.incrementAndGet();

        Alert alert = orchestrator.analyze(entry);
        if (alert != null) {
            alertManager.addAlert(alert);
            broadcastEvent("alert", alertToJson(alert));
        }
        broadcastEvent("log", logEntryToJson(entry));

        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"logEntry\":").append(logEntryToJson(entry)).append(",");
        json.append("\"threatDetected\":").append(alert != null);
        if (alert != null) {
            json.append(",\"alert\":").append(alertToJson(alert));
        }
        json.append("}");

        sendResponse(exchange, 200, "application/json", json.toString());
    }

    // --- Static File Handler ---

    private class StaticFileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/") || path.isEmpty()) {
                path = "/index.html";
            }

            // Security check against directory traversal
            if (path.contains("..")) {
                sendResponse(exchange, 403, "text/plain", "Forbidden");
                return;
            }

            byte[] data = loadResource("/web" + path);
            if (data == null) {
                // Try from local filesystem during dev
                File file = new File("src/main/resources/web" + path);
                if (file.exists() && file.isFile()) {
                    try (FileInputStream fis = new FileInputStream(file)) {
                        data = fis.readAllBytes();
                    }
                }
            }

            if (data == null) {
                sendResponse(exchange, 404, "text/html; charset=UTF-8",
                        "<h1>404 Not Found</h1><p>Resource " + escapeJson(path) + " was not found.</p>");
                return;
            }

            String contentType = getContentType(path);
            sendResponseBytes(exchange, 200, contentType, data);
        }

        private byte[] loadResource(String resourcePath) {
            try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
                if (is != null) {
                    return is.readAllBytes();
                }
            } catch (Exception ignored) {}
            return null;
        }

        private String getContentType(String path) {
            if (path.endsWith(".html")) return "text/html; charset=UTF-8";
            if (path.endsWith(".css")) return "text/css; charset=UTF-8";
            if (path.endsWith(".js")) return "application/javascript; charset=UTF-8";
            if (path.endsWith(".json")) return "application/json; charset=UTF-8";
            if (path.endsWith(".svg")) return "image/svg+xml";
            if (path.endsWith(".png")) return "image/png";
            if (path.endsWith(".ico")) return "image/x-icon";
            return "text/plain; charset=UTF-8";
        }
    }

    // --- JSON Serialization Helpers (Zero external dependencies) ---

    private String alertToJson(Alert a) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"id\":\"").append(Integer.toHexString(a.hashCode())).append("\",");
        sb.append("\"timestamp\":\"").append(a.getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("\",");
        sb.append("\"category\":\"").append(a.getCategory().name()).append("\",");
        sb.append("\"categoryDisplay\":\"").append(escapeJson(a.getCategory().toString())).append("\",");
        sb.append("\"severity\":\"").append(a.getSeverity().name()).append("\",");
        sb.append("\"riskScore\":").append(String.format(Locale.US, "%.1f", a.getRiskScore())).append(",");
        sb.append("\"sourceIp\":\"").append(escapeJson(a.getSourceIp())).append("\",");
        sb.append("\"affectedSystem\":\"").append(escapeJson(a.getAffectedSystem())).append("\",");
        sb.append("\"description\":\"").append(escapeJson(a.getDescription())).append("\",");
        sb.append("\"payload\":\"").append(a.getTriggeringLog() != null ? escapeJson(a.getTriggeringLog().getPayload()) : "").append("\",");
        sb.append("\"logType\":\"").append(a.getTriggeringLog() != null ? escapeJson(a.getTriggeringLog().getLogType()) : "").append("\"");
        sb.append("}");
        return sb.toString();
    }

    private String logEntryToJson(LogEntry e) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"timestamp\":\"").append(e.getTimestamp().format(DateTimeFormatter.ofPattern("HH:mm:ss"))).append("\",");
        sb.append("\"logType\":\"").append(escapeJson(e.getLogType())).append("\",");
        sb.append("\"ipAddress\":\"").append(escapeJson(e.getIpAddress())).append("\",");
        sb.append("\"requestType\":\"").append(escapeJson(e.getRequestType())).append("\",");
        sb.append("\"statusCode\":").append(e.getStatusCode()).append(",");
        sb.append("\"userInfo\":\"").append(escapeJson(e.getUserInfo() != null ? e.getUserInfo() : "-")).append("\",");
        sb.append("\"payload\":\"").append(escapeJson(e.getPayload())).append("\",");
        sb.append("\"rawLog\":\"").append(escapeJson(e.getRawLog())).append("\"");
        sb.append("}");
        return sb.toString();
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    private String parseJsonField(String json, String field, String defaultValue) {
        if (json == null) return defaultValue;
        String key = "\"" + field + "\"";
        int idx = json.indexOf(key);
        if (idx == -1) return defaultValue;
        int colon = json.indexOf(':', idx + key.length());
        if (colon == -1) return defaultValue;

        int start = colon + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        if (start >= json.length()) return defaultValue;

        if (json.charAt(start) == '"') {
            StringBuilder sb = new StringBuilder();
            boolean escape = false;
            for (int i = start + 1; i < json.length(); i++) {
                char c = json.charAt(i);
                if (escape) {
                    switch (c) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (i + 4 < json.length()) {
                                try {
                                    sb.append((char) Integer.parseInt(json.substring(i + 1, i + 5), 16));
                                    i += 4;
                                } catch (Exception ex) {
                                    sb.append('u');
                                }
                            } else {
                                sb.append('u');
                            }
                        }
                        default -> sb.append(c);
                    }
                    escape = false;
                } else if (c == '\\') {
                    escape = true;
                } else if (c == '"') {
                    return sb.toString();
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        } else {
            int end = start;
            while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}' && json.charAt(end) != ']') {
                end++;
            }
            return json.substring(start, end).trim();
        }
    }

    private int parseIntField(String json, String field, int defaultValue) {
        String val = parseJsonField(json, field, String.valueOf(defaultValue));
        try {
            return Integer.parseInt(val.replaceAll("[^0-9-]", ""));
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private double parseDoubleField(String json, String field, double defaultValue) {
        String val = parseJsonField(json, field, String.valueOf(defaultValue));
        try {
            return Double.parseDouble(val.replaceAll("[^0-9.-]", ""));
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private String readRequestBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody();
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[1024];
            int n;
            while ((n = is.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            return baos.toString(StandardCharsets.UTF_8);
        }
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        sendResponseBytes(exchange, statusCode, contentType, bytes);
    }

    private void sendResponseBytes(HttpExchange exchange, int statusCode, String contentType, byte[] bytes) throws IOException {
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", contentType);
        headers.set("Access-Control-Allow-Origin", "*");
        headers.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        headers.set("Access-Control-Allow-Headers", "Content-Type");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
