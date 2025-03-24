package com.offensivescanner.utils;

/**
 * Utility class for console output formatting, including colors and formatting.
 */
public class ConsoleUtils {

    // ANSI color codes
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_GREEN = "\u001B[32m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_BLUE = "\u001B[34m";
    private static final String ANSI_PURPLE = "\u001B[35m";
    private static final String ANSI_CYAN = "\u001B[36m";
    
    // ANSI style codes
    private static final String ANSI_BOLD = "\u001B[1m";
    
    private static boolean colorEnabled = true;
    
    /**
     * Print an ASCII art banner for the application
     * 
     * @param appName The application name
     * @param version The application version
     */
    public static void printBanner(String appName, String version) {
        System.out.println(colorize(ANSI_RED, ANSI_BOLD,
            "███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗ ██████╗ █████╗ ███╗   ██╗\n" +
            "██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗████╗  ██║\n" +
            "███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████╗██║     ███████║██╔██╗ ██║\n" + 
            "╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════██║██║     ██╔══██║██║╚██╗██║\n" +
            "███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████║╚██████╗██║  ██║██║ ╚████║\n" +
            "╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n"));

        System.out.println(colorize(ANSI_PURPLE, ANSI_BOLD, "                    S H 4 D 0 W S C 4 N N 3 R"));
        System.out.println(colorize(ANSI_CYAN, ANSI_BOLD, "                    " + appName + " v" + version));
        System.out.println(colorize(ANSI_GREEN, ANSI_BOLD, "                    Created by 5h4d0wn1k"));
        System.out.println(colorize(ANSI_YELLOW, ANSI_BOLD, "\n  [!] DISCLAIMER: Use only on systems you are authorized to scan!\n"));
    }
    /**
     * Print an informational message
     * 
     * @param message The message to print
     */
    public static void printInfo(String message) {
        System.out.println(colorize(ANSI_BLUE, ANSI_BOLD, "[*] ") + message);
    }
    
    /**
     * Print a success message
     * 
     * @param message The message to print
     */
    public static void printSuccess(String message) {
        System.out.println(colorize(ANSI_GREEN, ANSI_BOLD, "[+] ") + message);
    }
    
    /**
     * Print an error message
     * 
     * @param message The message to print
     */
    public static void printError(String message) {
        System.out.println(colorize(ANSI_RED, ANSI_BOLD, "[-] ") + message);
    }
    
    /**
     * Print a warning message
     * 
     * @param message The message to print
     */
    public static void printWarning(String message) {
        System.out.println(colorize(ANSI_YELLOW, ANSI_BOLD, "[!] ") + message);
    }
    
    /**
     * Print a debug message
     * 
     * @param message The message to print
     */
    public static void printDebug(String message) {
        System.out.println(colorize(ANSI_PURPLE, ANSI_BOLD, "[D] ") + message);
    }
    
    /**
     * Print a verbose message
     * 
     * @param message The message to print
     */
    public static void printVerbose(String message) {
        System.out.println(colorize(ANSI_CYAN, ANSI_BOLD, "[V] ") + message);
    }
    
    /**
     * Print a section header
     * 
     * @param title The section title
     */
    public static void printSectionHeader(String title) {
        System.out.println("\n" + colorize(ANSI_BLUE, ANSI_BOLD, "=== " + title + " ==="));
    }
    
    /**
     * Colorize a string with ANSI color codes
     * 
     * @param color The color ANSI code
     * @param style The style ANSI code
     * @param text The text to colorize
     * @return The colorized string
     */
    private static String colorize(String color, String style, String text) {
        if (!colorEnabled) {
            return text;
        }
        return color + style + text + ANSI_RESET;
    }
    
    /**
     * Enable or disable colored output
     * 
     * @param enabled Whether colors should be enabled
     */
    public static void setColorEnabled(boolean enabled) {
        colorEnabled = enabled;
    }
    
    /**
     * Check if colored output is enabled
     * 
     * @return Whether colors are enabled
     */
    public static boolean isColorEnabled() {
        return colorEnabled;
    }
} 