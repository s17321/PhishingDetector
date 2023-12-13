package com.piotr.phishingdetector.java;

// Ten program jest treningowy..




import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class PhishingDetector {

    private static final String PHISHING_API_URL = "https://cloud.google.com/web-risk/docs/reference/rest/v1eap1/TopLevel/evaluateUri";

    public static boolean isPhishing(String message) {
        // Analiza treści wiadomości, sprawdzanie czy zawiera podejrzane frazy, itp.
        boolean containsPhishingContent = analyzeContent(message);

        if (containsPhishingContent) {
            // Jeśli zawiera podejrzane treści, odrzuć wiadomość jako potencjalny phishing
            return true;
        } else {
            // Jeśli nie zawiera podejrzanych treści, sprawdź URL przy użyciu zewnętrznego serwisu
            boolean isPhishingURL = checkURL(message);
            return isPhishingURL;
        }
    }

    private static boolean analyzeContent(String message) {
        // Implementacja analizy treści wiadomości
        // Sprawdzanie czy zawiera podejrzane frazy, słowa kluczowe, itp.
        // Możesz dostosować tę metodę do własnych potrzeb
        return false;
    }

    private static boolean checkURL(String url) {
        // Pobierz URL z treści wiadomości (np. przy użyciu regex)
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(PHISHING_API_URL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(buildRequestBody(url)))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            return analyzePhishingResponse(response.body());
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static String extractURL(String message) {
        // Implementacja ekstrakcji URL z treści wiadomości
        // Możesz użyć regex lub innych metod, w zależności od formatu wiadomości
        return "https://example.com";  // Przykładowy URL
    }

    private static boolean callPhishingAPI(String url) {
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(PHISHING_API_URL))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"url\": \"" + url + "\"}"))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Analiza odpowiedzi z serwisu
            // Jeśli odpowiedź wskazuje, że URL jest podejrzany, zwróć true
            return analyzePhishingResponse(response.body());
        } catch (Exception e) {
            e.printStackTrace();
            // W przypadku błędu, zwróć false (na wszelki wypadek)
            return false;
        }
    }

    private static String buildRequestBody(String url) {
        // Tworzenie treści żądania do API zgodnie z wymaganiami
        return String.format("{\"uri\": \"%s\", \"threatTypes\": [\"SOCIAL_ENGINEERING\", \"MALWARE\", \"UNWANTED_SOFTWARE\"], \"allowScan\": true}", url);
    }
    private static boolean analyzePhishingResponse(String responseBody) {
        // Analiza odpowiedzi z serwisu
        // Możesz dostosować tę metodę do formatu odpowiedzi serwisu
        // W przykładowym kodzie zakładałem prostą analizę JSONa
        return responseBody.contains("\"phishing\": true");
    }

    public static void main(String[] args) {
        String sampleMessage = "{\"sender\": \"234100200300\", \"recipient\": \"48700800999\", \"message\": \"Dzień dobry. W związku z audytem nadzór finansowy w naszym banku proszą o potwierdzanie danych pod adresem: https://www.m-bonk.pl.ng/personal-data\"}";
        boolean isPhishing = isPhishing(sampleMessage);
        System.out.println("Is phishing: " + isPhishing);
    }
}