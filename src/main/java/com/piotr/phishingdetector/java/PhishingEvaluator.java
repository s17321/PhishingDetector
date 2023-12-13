package com.piotr.phishingdetector.java;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

// tu by trzeba było dodać url'e aby były pobierane z pliku json z message
//SMSParser sobie to dzieli na poszczególne kategorie.
public class PhishingEvaluator {

    public static void main(String[] args) {
        // Przykładowy URL do oceny
        String urlToEvaluate = "https://www.youtube.com";

        // Przykładowe threatTypes
        String[] threatTypes = {"SOCIAL_ENGINEERING", "MALWARE"};

        // Wywołaj funkcję oceny
        evaluatePhishing(urlToEvaluate, threatTypes);
    }

    public static void evaluatePhishing(String url, String[] threatTypes) {
        try {
            // Utwórz URL do endpointa API
            URL apiEndpoint = new URL("https://webrisk.googleapis.com/v1/projects/testowe-407922:evaluate");

            // Otwórz połączenie HTTP
            HttpURLConnection connection = (HttpURLConnection) apiEndpoint.openConnection();

            // Ustaw metody i nagłówki
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Authorization", "AIzaSyCGON0RcyFb-k2TfRfEBwTw5CS3g3sla4I");

            // Włącz obsługę do wysyłania danych w ciele żądania
            connection.setDoOutput(true);


            // Przygotuj dane JSON do wysłania
            String jsonInputString = "{\"uri\": \"" + url + "\", \"threatTypes\": " + toJsonArray(threatTypes) + ", \"allowScan\": true}";

            // Uzyskaj strumień wyjściowy do wysłania danych
            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonInputString.getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Debugowanie: Wydrukuj informacje o zapytaniu HTTP
            System.out.println("Request URL: " + apiEndpoint.toString());
            int responseCode = connection.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            // Odczytaj odpowiedź
            try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine = null;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }
                System.out.println(response.toString());
            }

            // Zamknij połączenie
            connection.disconnect();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Konwersja tablicy na reprezentację JSON
    public static String toJsonArray(String[] array) {
        StringBuilder jsonArray = new StringBuilder("[");
        for (int i = 0; i < array.length; i++) {
            jsonArray.append("\"").append(array[i]).append("\"");
            if (i < array.length - 1) {
                jsonArray.append(",");
            }
        }
        jsonArray.append("]");
        return jsonArray.toString();
    }
}
//AIzaSyCGON0RcyFb-k2TfRfEBwTw5CS3g3sla4I