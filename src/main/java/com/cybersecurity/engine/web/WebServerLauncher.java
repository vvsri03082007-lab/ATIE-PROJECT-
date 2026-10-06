package com.cybersecurity.engine.web;

import java.awt.Desktop;
import java.net.URI;

/**
 * Standalone launcher for the ATIE Web Operations Center.
 */
public class WebServerLauncher {
    private static final String CYAN = "\u001B[36m";
    private static final String GREEN = "\u001B[32m";
    private static final String RESET = "\u001B[0m";
    private static final String BOLD = "\u001B[1m";

    public static void main(String[] args) {
        int port = 8080;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (Exception ignored) {}
        }

        System.out.println(CYAN + BOLD);
        System.out.println("╔══════════════════════════════════════════════════════════════════════╗");
        System.out.println("║         ATIE CYBERSECURITY OPERATIONS CENTER (WEB SERVER)            ║");
        System.out.println("║             Next-Gen SIEM Live Telemetry & Detection Console         ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════════╝" + RESET);

        try {
            WebServer webServer = new WebServer(port);
            webServer.start();

            String url = "http://localhost:" + port + "/";
            System.out.println("\n" + GREEN + BOLD + ">>> Dashboard live at: " + url + RESET);
            System.out.println(CYAN + "Press Ctrl+C in terminal to stop the web server." + RESET + "\n");

            // Try to open default browser
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                try {
                    Desktop.getDesktop().browse(new URI(url));
                } catch (Exception ignored) {}
            }

            // Keep main thread alive
            Thread.currentThread().join();

        } catch (Exception e) {
            System.err.println("Failed to start WebServer: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
