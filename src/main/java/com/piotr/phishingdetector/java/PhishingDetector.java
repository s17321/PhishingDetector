package com.piotr.phishingdetector.java;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class PhishingDetector {
    private static final String PHISHING_SERVICE_URL = "https://cloud.google.com/web-risk/docs/reference/rest/v1eap1/TopLevel/evaluateUri";
    private static final String SMS_NUMBER = "123456789"; // Określony numer do odbierania SMS-ów

    public static void main(String[] args) {
        String urlToCheck = "https://www.m-bonk.pl.ng/personal-data";

        if (isPhishing(urlToCheck)) {
            System.out.println("Phishing detected!");
        } else {
            System.out.println("No phishing detected.");
        }

        // Przykład obsługi SMS-ów
        handleSMS("START"); // Użytkownik wyraża chęć skorzystania z usługi
        handleSMS("STOP");  // Użytkownik wyraża rezygnację z usługi
    }

    public static boolean isPhishing(String url) {
        try {
            // Tworzymy klienta HTTP
            HttpClient client = HttpClient.newHttpClient();

            // Tworzymy zapytanie HTTP GET z adresem URL serwisu oceny phishingu
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(new URI(PHISHING_SERVICE_URL + "?url=" + url))
                    .GET()
                    .build();

            // Wykonujemy zapytanie i odbieramy odpowiedź
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            // Sprawdzamy status odpowiedzi (200 oznacza sukces)
            if (response.statusCode() == 200) {
                // Tutaj możesz analizować zawartość odpowiedzi (np. JSON) i wyciągać informacje o ocenie phishingu.
                // Poniżej znajduje się tylko przykład, można dostosować do rzeczywistego interfejsu serwisu.

                // Zakładamy, że odpowiedź JSON zawiera pole "isPhishing", które informuje o ocenie.
                boolean isPhishing = response.body().contains("\"isPhishing\": true");

                return isPhishing;
            } else {
                // Obsługa błędu
                System.out.println("Error while evaluating the URL: " + response.statusCode());
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    private static void handleSMS(String message) {
        // Obsługa SMS-ów, np. analiza treści i aktualizacja preferencji użytkownika
        if (message.equalsIgnoreCase("START")) {
            System.out.println("User opted in to the service.");
            // Tutaj możesz dodać kod do aktualizacji preferencji użytkownika w bazie danych.
        } else if (message.equalsIgnoreCase("STOP")) {
            System.out.println("User opted out of the service.");
            // Tutaj możesz dodać kod do aktualizacji preferencji użytkownika w bazie danych.
        } else {
            System.out.println("Unknown SMS command.");
        }
    }
}