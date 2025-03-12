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

                        HttpResponse selectedResponse = fetchUrl(selectedResult.url, 0);
                        if (selectedResponse != null) {
                            System.out.println(extractReadableTextFromHtml(selectedResponse.body));
                        }
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

            url = cleanUrl(url);

            results.add(new SearchResult(title, url, description));
        }

        return results;
    }

    private static String cleanUrl(String url) {
        url = decodeHtmlEntities(url);

        int ampRutIndex = url.indexOf("&rut=");
        if (ampRutIndex != -1) {
            url = url.substring(0, ampRutIndex);
        }

        return url;
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
        String noTags = html.replaceAll("<[^>]*>", "");

        return decodeHtmlEntities(noTags).trim();
    }

    private static String decodeHtmlEntities(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }

        Pattern decimalPattern = Pattern.compile("&#(\\d+);");
        Matcher decimalMatcher = decimalPattern.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (decimalMatcher.find()) {
            String replacement = String.valueOf((char) Integer.parseInt(decimalMatcher.group(1)));
            decimalMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        decimalMatcher.appendTail(sb);
        text = sb.toString();

        Pattern hexPattern = Pattern.compile("&#x([0-9a-fA-F]+);");
        Matcher hexMatcher = hexPattern.matcher(text);
        sb = new StringBuffer();
        while (hexMatcher.find()) {
            String replacement = String.valueOf((char) Integer.parseInt(hexMatcher.group(1), 16));
            hexMatcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        hexMatcher.appendTail(sb);
        text = sb.toString();

        Map<String, String> entities = new HashMap<>();
        entities.put("&quot;", "\"");
        entities.put("&amp;", "&");
        entities.put("&lt;", "<");
        entities.put("&gt;", ">");
        entities.put("&nbsp;", " ");
        entities.put("&apos;", "'");
        entities.put("&rsquo;", "'");
        entities.put("&lsquo;", "'");
        entities.put("&rdquo;", "\"");
        entities.put("&ldquo;", "\"");
        entities.put("&ndash;", "–");
        entities.put("&mdash;", "—");
        entities.put("&euro;", "€");
        entities.put("&pound;", "£");
        entities.put("&yen;", "¥");
        entities.put("&copy;", "©");
        entities.put("&reg;", "®");
        entities.put("&trade;", "™");
        entities.put("&agrave;", "à");
        entities.put("&aacute;", "á");
        entities.put("&acirc;", "â");
        entities.put("&atilde;", "ã");
        entities.put("&auml;", "ä");
        entities.put("&aring;", "å");
        entities.put("&aelig;", "æ");
        entities.put("&ccedil;", "ç");
        entities.put("&egrave;", "è");
        entities.put("&eacute;", "é");
        entities.put("&ecirc;", "ê");
        entities.put("&euml;", "ë");
        entities.put("&igrave;", "ì");
        entities.put("&iacute;", "í");
        entities.put("&icirc;", "î");
        entities.put("&iuml;", "ï");
        entities.put("&ntilde;", "ñ");
        entities.put("&ograve;", "ò");
        entities.put("&oacute;", "ó");
        entities.put("&ocirc;", "ô");
        entities.put("&otilde;", "õ");
        entities.put("&ouml;", "ö");
        entities.put("&oslash;", "ø");
        entities.put("&szlig;", "ß");
        entities.put("&ugrave;", "ù");
        entities.put("&uacute;", "ú");
        entities.put("&ucirc;", "û");
        entities.put("&uuml;", "ü");
        entities.put("&yuml;", "ÿ");

        for (Map.Entry<String, String> entry : entities.entrySet()) {
            text = text.replace(entry.getKey(), entry.getValue());
        }

        return text;
    }

    private record HttpResponse(int statusCode, Map<String, String> headers, String body) implements Serializable {
        @Serial
        private static final long serialVersionUID = 1L;

        public String getReadableContent() {
            String contentType = headers.getOrDefault("Content-Type", "").toLowerCase();

            if (contentType.contains("application/json")) {
                return formatJson(body);
            } else if (contentType.contains("text/html")) {
                return extractReadableTextFromHtml(body);
            } else {
                return body;
            }
        }

        private String extractReadableTextFromHtml(String html) {
            // Remove script tags and their content
            String noScripts = html.replaceAll("<script[^>]*>[\\s\\S]*?</script>", "");

            // Remove style tags and their content
            String noStyles = noScripts.replaceAll("<style[^>]*>[\\s\\S]*?</style>", "");

            // Extract text from specific readable elements (add more as needed)
            StringBuilder result = new StringBuilder();

            // Extract title
            Pattern titlePattern = Pattern.compile("<title[^>]*>(.*?)</title>", Pattern.DOTALL);
            Matcher titleMatcher = titlePattern.matcher(noStyles);
            if (titleMatcher.find()) {
                result.append("Title: ").append(cleanHtml(titleMatcher.group(1))).append("\n\n");
            }

            // Extract text from paragraph tags
            Pattern pPattern = Pattern.compile("<p[^>]*>(.*?)</p>", Pattern.DOTALL);
            Matcher pMatcher = pPattern.matcher(noStyles);
            while (pMatcher.find()) {
                String paragraph = cleanHtml(pMatcher.group(1));
                if (!paragraph.isBlank()) {
                    result.append(paragraph).append("\n\n");
                }
            }

            // Extract text from heading tags (h1-h6)
            for (int i = 1; i <= 6; i++) {
                Pattern hPattern = Pattern.compile("<h" + i + "[^>]*>(.*?)</h" + i + ">", Pattern.DOTALL);
                Matcher hMatcher = hPattern.matcher(noStyles);
                while (hMatcher.find()) {
                    String heading = cleanHtml(hMatcher.group(1));
                    if (!heading.isBlank()) {
                        result.append(heading).append("\n\n");
                    }
                }
            }

            // Extract text from list items
            Pattern liPattern = Pattern.compile("<li[^>]*>(.*?)</li>", Pattern.DOTALL);
            Matcher liMatcher = liPattern.matcher(noStyles);
            while (liMatcher.find()) {
                String item = cleanHtml(liMatcher.group(1));
                if (!item.isBlank()) {
                    result.append("• ").append(item).append("\n");
                }
            }

            // Extract text from divs (can contain important content)
            Pattern divPattern = Pattern.compile("<div[^>]*>(.*?)</div>", Pattern.DOTALL);
            Matcher divMatcher = divPattern.matcher(noStyles);
            Set<String> processedDivs = new HashSet<>();
            while (divMatcher.find()) {
                String divContent = divMatcher.group(1);
                // Skip divs that just contain other divs to avoid duplication
                if (!divContent.contains("<div") && !divContent.isBlank()) {
                    String cleanedDiv = cleanHtml(divContent);
                    if (!cleanedDiv.isBlank() && !processedDivs.contains(cleanedDiv)) {
                        processedDivs.add(cleanedDiv);
                        result.append(cleanedDiv).append("\n\n");
                    }
                }
            }

            // Get any remaining plain text
            String cleanedHtml = cleanHtml(noStyles);

            // If we didn't extract anything usable, fall back to the general cleaning
            if (result.length() < 100 && !cleanedHtml.isBlank()) {
                return cleanedHtml;
            }

            return result.toString().trim();
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

    private static void extractContentFromTags(String content, StringBuilder result) {
        for (int i = 1; i <= 6; i++) {
            Pattern hPattern = Pattern.compile("<h" + i + "[^>]*>(.*?)</h" + i + ">", Pattern.DOTALL);
            Matcher hMatcher = hPattern.matcher(content);
            while (hMatcher.find()) {
                String heading = cleanHtml(hMatcher.group(1));
                if (!heading.isBlank()) {
                    result.append(heading).append("\n\n");
                }
            }
        }

        Pattern pPattern = Pattern.compile("<p[^>]*>(.*?)</p>", Pattern.DOTALL);
        Matcher pMatcher = pPattern.matcher(content);
        while (pMatcher.find()) {
            String paragraph = cleanHtml(pMatcher.group(1));
            if (!paragraph.isBlank()) {
                result.append(paragraph).append("\n\n");
            }
        }

        Pattern liPattern = Pattern.compile("<li[^>]*>(.*?)</li>", Pattern.DOTALL);
        Matcher liMatcher = liPattern.matcher(content);
        while (liMatcher.find()) {
            String item = cleanHtml(liMatcher.group(1));
            if (!item.isBlank()) {
                result.append("• ").append(item).append("\n");
            }
        }

        Pattern divPattern = Pattern.compile("<div[^>]*class=[\"'](?:content|main|article|text|body)[^\"']*[\"'][^>]*>(.*?)</div>", Pattern.DOTALL);
        Matcher divMatcher = divPattern.matcher(content);
        Set<String> processedDivs = new HashSet<>();
        while (divMatcher.find()) {
            String divContent = divMatcher.group(1);
            if (!divContent.contains("<div") && !divContent.isBlank()) {
                String cleanedDiv = cleanHtml(divContent);
                if (!cleanedDiv.isBlank() && !processedDivs.contains(cleanedDiv)) {
                    processedDivs.add(cleanedDiv);
                    result.append(cleanedDiv).append("\n\n");
                }
            }
        }

        if (result.length() < 200) {
            divPattern = Pattern.compile("<div[^>]*>(.*?)</div>", Pattern.DOTALL);
            divMatcher = divPattern.matcher(content);
            while (divMatcher.find()) {
                String divContent = divMatcher.group(1);
                if (!divContent.contains("<div") && !divContent.isBlank()) {
                    String cleanedDiv = cleanHtml(divContent);
                    if (!cleanedDiv.isBlank() && !processedDivs.contains(cleanedDiv) && cleanedDiv.length() > 50) {
                        processedDivs.add(cleanedDiv);
                        result.append(cleanedDiv).append("\n\n");
                    }
                }
            }
        }

        Pattern spanPattern = Pattern.compile("<span[^>]*>(.*?)</span>", Pattern.DOTALL);
        Matcher spanMatcher = spanPattern.matcher(content);
        Set<String> processedSpans = new HashSet<>();
        while (spanMatcher.find()) {
            String spanContent = spanMatcher.group(1);
            if (!spanContent.isBlank() && !spanContent.contains("<")) {
                String cleanedSpan = cleanHtml(spanContent);
                if (!cleanedSpan.isBlank() && !processedSpans.contains(cleanedSpan) && cleanedSpan.length() > 50) {
                    processedSpans.add(cleanedSpan);
                    result.append(cleanedSpan).append("\n\n");
                }
            }
        }
    }

    private static String extractReadableTextFromHtml(String html) {
        String noScripts = html.replaceAll("<script[^>]*>[\\s\\S]*?</script>", "");

        String noStyles = noScripts.replaceAll("<style[^>]*>[\\s\\S]*?</style>", "");

        noStyles = noStyles.replaceAll("<head[^>]*>[\\s\\S]*?</head>", "");

        noStyles = noStyles.replaceAll("<meta[^>]*>", "");

        noStyles = noStyles.replaceAll("<link[^>]*>", "");

        noStyles = noStyles.replaceAll("<iframe[^>]*>[\\s\\S]*?</iframe>", "");

        noStyles = noStyles.replaceAll("<form[^>]*>[\\s\\S]*?</form>", "");

        noStyles = noStyles.replaceAll("<svg[^>]*>[\\s\\S]*?</svg>", "");

        noStyles = noStyles.replaceAll("<nav[^>]*>[\\s\\S]*?</nav>", "");

        noStyles = noStyles.replaceAll("<header[^>]*>[\\s\\S]*?</header>", "");

        noStyles = noStyles.replaceAll("<footer[^>]*>[\\s\\S]*?</footer>", "");

        StringBuilder result = new StringBuilder();

        Pattern titlePattern = Pattern.compile("<title[^>]*>(.*?)</title>", Pattern.DOTALL);
        Matcher titleMatcher = titlePattern.matcher(noStyles);
        if (titleMatcher.find()) {
            result.append("Title: ").append(cleanHtml(titleMatcher.group(1))).append("\n\n");
        }

        Pattern articlePattern = Pattern.compile("<article[^>]*>(.*?)</article>", Pattern.DOTALL);
        Matcher articleMatcher = articlePattern.matcher(noStyles);
        boolean foundArticle = false;
        while (articleMatcher.find()) {
            foundArticle = true;
            String articleContent = articleMatcher.group(1);
            extractContentFromTags(articleContent, result);
        }

        if (!foundArticle) {
            Pattern mainPattern = Pattern.compile("<main[^>]*>(.*?)</main>", Pattern.DOTALL);
            Matcher mainMatcher = mainPattern.matcher(noStyles);
            boolean foundMain = false;
            while (mainMatcher.find()) {
                foundMain = true;
                String mainContent = mainMatcher.group(1);
                extractContentFromTags(mainContent, result);
            }

            if (!foundMain) {
                Pattern bodyPattern = Pattern.compile("<body[^>]*>(.*?)</body>", Pattern.DOTALL);
                Matcher bodyMatcher = bodyPattern.matcher(noStyles);
                if (bodyMatcher.find()) {
                    String bodyContent = bodyMatcher.group(1);
                    extractContentFromTags(bodyContent, result);
                } else {
                    extractContentFromTags(noStyles, result);
                }
            }
        }

        if (result.length() < 200) {
            String plainText = noStyles.replaceAll("<[^>]*>", " ")
                    .replaceAll("\\s+", " ")
                    .trim();

            if (!plainText.isEmpty()) {
                result.append(plainText);
            }
        }

        return result.toString().trim();
    }
}