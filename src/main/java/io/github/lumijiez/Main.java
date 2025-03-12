package io.github.lumijiez;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

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

    private static void fetchAndPrintUrl(String url) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        HttpResponse response = fetchUrl(url, 0);
        if (response != null) {
            System.out.println(response.getReadableContent());
        }
    }

    private static void performSearch(String searchTerm) throws IOException, NoSuchAlgorithmException, KeyManagementException {
        String encodedTerm = URLEncoder.encode(searchTerm, StandardCharsets.UTF_8);
        String searchUrl = "https://duckduckgo.com/html/?q=" + encodedTerm;

        HttpResponse response = fetchUrl(searchUrl, 0);

        if (response.statusCode() == 200) {
            List<SearchResult> results = extractSearchResults(response.body());

            System.out.println("Search results for: " + searchTerm);
            System.out.println("------------------------------------");

            int count = 0;
            for (SearchResult result : results) {
                count++;
                System.out.println(count + ". " + result.title);
                System.out.println("   " + result.url);
                System.out.println("   " + result.description);
                System.out.println();

                if (count >= 10) {
                    break;
                }
            }

            Scanner scanner = new Scanner(System.in);
            System.out.println("Enter a number to open the result (1-10), or 'q' to quit:");
            String input = scanner.nextLine().trim();

            if (!input.equalsIgnoreCase("q")) {
                try {
                    int resultNum = Integer.parseInt(input);
                    if (resultNum >= 1 && resultNum <= Math.min(10, results.size())) {
                        SearchResult selectedResult = results.get(resultNum - 1);
                        System.out.println("Fetching: " + selectedResult.url);
                        fetchAndPrintUrl(selectedResult.url);
                    } else {
                        System.out.println("Invalid result number");
                    }
                } catch (NumberFormatException e) {
                    System.out.println("Invalid input");
                }
            }
        } else {
            System.err.println("Search failed with status code: " + response.statusCode());
        }
    }

    private static HttpResponse fetchUrl(String url, int redirectCount)
            throws IOException, NoSuchAlgorithmException, KeyManagementException {

        @SuppressWarnings("deprecation")
        URL urlObj = new URL(url);
        String host = urlObj.getHost();
        String path = urlObj.getPath();
        if (path.isEmpty()) {
            path = "/";
        }
        String query = urlObj.getQuery();
        if (query != null) {
            path += "?" + query;
        }

        boolean isHttps = url.startsWith("https://");
        int port = urlObj.getPort() == -1 ? (isHttps ? HTTPS_PORT : HTTP_PORT) : urlObj.getPort();

        String requestBuilder = "GET " + path + " HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "User-Agent: " + USER_AGENT + "\r\n" +
                "Connection: close\r\n" +
                "Accept: text/html,application/json\r\n" +
                "\r\n";

        Socket socket;
        if (isHttps) {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, null, null);
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            socket = sslSocketFactory.createSocket(host, port);
        } else {
            socket = new Socket(host, port);
        }

        socket.setSoTimeout(10000);

        OutputStream out = socket.getOutputStream();
        out.write(requestBuilder.getBytes());
        out.flush();

        InputStream in = socket.getInputStream();
        ByteArrayOutputStream responseBytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            responseBytes.write(buffer, 0, bytesRead);
        }

        socket.close();

        String responseStr = responseBytes.toString(StandardCharsets.UTF_8);
        HttpResponse response = parseResponse(responseStr);

        if (response.statusCode() >= 300 && response.statusCode() < 400) {
            String redirectUrl = response.headers().get("Location");
            if (redirectUrl != null) {
                if (!redirectUrl.startsWith("http")) {
                    redirectUrl = urlObj.getProtocol() + "://" + host +
                            (redirectUrl.startsWith("/") ? "" : "/") + redirectUrl;
                }
                return fetchUrl(redirectUrl, redirectCount + 1);
            }
        }

        cache.put(url, new CacheEntry(response));
        return response;
    }

    private record HttpResponse(int statusCode, Map<String, String> headers, String body) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        public String getReadableContent() {
            String contentType = headers.getOrDefault("Content-Type", "").toLowerCase();

            if (contentType.contains("application/json")) {
                return formatJson(body);
            } else if (contentType.contains("text/html")) {
                return cleanHtml(body);
            } else {
                return body;
            }
        }

        private String formatJson(String json) {
            StringBuilder formatted = new StringBuilder();
            int indentLevel = 0;
            boolean inQuotes = false;

            for (char c : json.toCharArray()) {
                if (c == '\"' && !inQuotes) {
                    inQuotes = true;
                    formatted.append(c);
                } else if (c == '\"') {
                    inQuotes = false;
                    formatted.append(c);
                } else if (!inQuotes && (c == '{' || c == '[')) {
                    indentLevel++;
                    formatted.append(c).append("\n").append(" ".repeat(indentLevel * 2));
                } else if (!inQuotes && (c == '}' || c == ']')) {
                    indentLevel--;
                    formatted.append("\n").append(" ".repeat(indentLevel * 2)).append(c);
                } else if (!inQuotes && c == ',') {
                    formatted.append(c).append("\n").append(" ".repeat(indentLevel * 2));
                } else if (!inQuotes && c == ':') {
                    formatted.append(c).append(" ");
                } else {
                    formatted.append(c);
                }
            }

            return formatted.toString();
        }
    }

    private record SearchResult(String title, String url, String description) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
    }
}