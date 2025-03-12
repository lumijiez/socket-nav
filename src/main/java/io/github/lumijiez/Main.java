package io.github.lumijiez;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {
    private static final int HTTP_PORT = 80;
    private static final int HTTPS_PORT = 443;
    private static final int MAX_REDIRECTS = 5;
    private static Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private static final String USER_AGENT = "Go2Web/1.0";
    private static final long CACHE_EXPIRY_TIME = TimeUnit.MINUTES.toMillis(5);
    private static final String CACHE_FILE = "go2web_cache.ser";

    public static void main(String[] args) {
        loadCacheFromFile();

        if (args.length < 1) {
            printHelp();
            return;
        }

        try {
            processArgs(args);
            saveCacheToFile();
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadCacheFromFile() {
        File cacheFile = new File(CACHE_FILE);
        if (cacheFile.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(cacheFile))) {
                cache = (ConcurrentHashMap<String, CacheEntry>) ois.readObject();

                cache.entrySet().removeIf(stringCacheEntryEntry -> stringCacheEntryEntry.getValue().isExpired());

                System.out.println("Cache loaded from file with " + cache.size() + " entries");
            } catch (Exception e) {
                System.err.println("Error loading cache from file: " + e.getMessage());
                cache = new ConcurrentHashMap<>();
            }
        }
    }

    private static void saveCacheToFile() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(CACHE_FILE))) {
            oos.writeObject(cache);
            System.out.println("Cache saved to file with " + cache.size() + " entries");
        } catch (Exception e) {
            System.err.println("Error saving cache to file: " + e.getMessage());
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

    private static HttpResponse fetchUrl(String url, int redirectCount)
            throws IOException, NoSuchAlgorithmException, KeyManagementException {
        if (redirectCount > MAX_REDIRECTS) {
            throw new IOException("Too many redirects");
        }

        CacheEntry cachedResponse = cache.get(url);
        if (cachedResponse != null && !cachedResponse.isExpired()) {
            System.out.println("CACHE HIT FOUND AND LOADED!");
            return cachedResponse.getResponse();
        }

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

    private static HttpResponse parseResponse(String responseStr) {
        int headerEnd = responseStr.indexOf("\r\n\r\n");
        if (headerEnd == -1) {
            headerEnd = responseStr.indexOf("\n\n");
        }

        if (headerEnd == -1) {
            return new HttpResponse(500, new HashMap<>(), "Invalid response from server");
        }

        String headersStr = responseStr.substring(0, headerEnd);
        String body = headerEnd + 4 <= responseStr.length() ? responseStr.substring(headerEnd + 4) : "";

        String[] headerLines = headersStr.split("\r\n|\n");
        String statusLine = headerLines[0];

        Pattern statusPattern = Pattern.compile("HTTP/\\d\\.\\d\\s+(\\d+)\\s+(.*)");
        Matcher statusMatcher = statusPattern.matcher(statusLine);

        if (!statusMatcher.matches()) {
            return new HttpResponse(500, new HashMap<>(), "Invalid status line: " + statusLine);
        }

        int statusCode = Integer.parseInt(statusMatcher.group(1));
        Map<String, String> headers = new HashMap<>();

        for (int i = 1; i < headerLines.length; i++) {
            String line = headerLines[i];
            int colonIndex = line.indexOf(':');
            if (colonIndex != -1) {
                String key = line.substring(0, colonIndex).trim();
                String value = line.substring(colonIndex + 1).trim();
                headers.put(key, value);
            }
        }

        return new HttpResponse(statusCode, headers, body);
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

    private static List<SearchResult> extractSearchResults(String html) {
        List<SearchResult> results = new ArrayList<>();

        Pattern pattern = Pattern.compile("<h2 class=\"result__title\">.*?<a.*?href=\"(.*?)\".*?>(.*?)</a>.*?<a.*?class=\"result__snippet\".*?>(.*?)</a>",
                Pattern.DOTALL);
        Matcher matcher = pattern.matcher(html);

        while (matcher.find()) {
            String url = matcher.group(1);
            String title = cleanHtml(matcher.group(2));
            String description = cleanHtml(matcher.group(3));

            if (url.startsWith("//duckduckgo.com/l/?uddg=")) {
                url = extractRedirectUrl(url);
            }

            results.add(new SearchResult(title, url, description));
        }

        return results;
    }

    private static String extractRedirectUrl(String url) {
        if (url.contains("uddg=")) {
            int start = url.indexOf("uddg=") + 5;
            String encodedUrl = url.substring(start);
            return URLDecoder.decode(encodedUrl, StandardCharsets.UTF_8);
        }
        return url;
    }

    private static String cleanHtml(String html) {
        return html.replaceAll("<[^>]*>", "")
                .replaceAll("&quot;", "\"")
                .replaceAll("&amp;", "&")
                .replaceAll("&lt;", "<")
                .replaceAll("&gt;", ">")
                .replaceAll("&nbsp;", " ")
                .trim();
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

    private static class CacheEntry implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
        private final HttpResponse response;
        private final long expiryTime;

        public CacheEntry(HttpResponse response) {
            this.response = response;
            this.expiryTime = System.currentTimeMillis() + CACHE_EXPIRY_TIME;
        }

        public HttpResponse getResponse() {
            return response;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }

    private record SearchResult(String title, String url, String description) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;
    }
}