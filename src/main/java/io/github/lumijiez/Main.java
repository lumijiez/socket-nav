package io.github.lumijiez;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class Main {
    private static final int HTTP_PORT = 80;
    private static final int HTTPS_PORT = 443;
    private static final String USER_AGENT = "Go2Web/1.0";
    public static void main(String[] args) {
        if (args.length < 1) {
            printHelp();
            return;
        }

        try {
            processArgs(args);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void processArgs(String[] args) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        String option = args[0];

        switch (option) {
            case "-u":
                if (args.length < 2) {
                    System.err.println("Error: URL required");
                    System.exit(1);
                }
                String url = args[1];
                if (!url.startsWith("http://") && !url.startsWith("https://")) {
                    url = "https://" + url;
                }
                fetchAndPrintUrl(url);
                break;

            case "-s":
                if (args.length < 2) {
                    System.err.println("Error: Search term required");
                    System.exit(1);
                }
                String searchTerm = args[1];
                performSearch(searchTerm);
                break;

            case "-h":
                printHelp();
                break;

            default:
                System.err.println("Error: Unknown option: " + option);
                printHelp();
                System.exit(1);
        }
    }

    private static void printHelp() {
        System.out.println("Usage:");
        System.out.println("  go2web -u <URL>         # make an HTTP request to the specified URL and print the response");
        System.out.println("  go2web -s <search-term> # make an HTTP request to search the term using DuckDuckGo and print top 10 results");
        System.out.println("  go2web -h               # show this help");
    }
}