package com.piotr.phishingdetector.java;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import static com.piotr.phishingdetector.java.PhishingDetector.*;

// tu by trzeba było dodać url'e aby były pobierane z pliku json z message
//SMSParser sobie to dzieli na poszczególne kategorie.
public class PhishingEvaluator {

    private static final String PHISHING_API_URL = "https://webrisk.googleapis.com/v1eap1:evaluateUri?key=\" + API_KEY";

    private static final String API_KEY = "AIzaSyCGON0RcyFb-k2TfRfEBwTw5CS3g3sla4I";  // Zastąp to swoim kluczem API

    public static void main(String[] args) {
        try {
            // Wczytaj zawartość pliku SMS.json
            String jsonString = readJsonFile("SMS.json");

            if (jsonString != null) {
                // Wyświetl dodatkowy komunikat przed zawartością pliku
                System.out.println("Pomyślnie wczytano zawartość pliku SMS.json.");

                // Wyświetl zawartość pliku
                System.out.println("Zawartość pliku SMS.json:");
                System.out.println(jsonString);

                String url = extractURLFromJSON(jsonString);

                if (url != null) {
                    // Wyświetl URL przed przekazaniem do usługi Web Risk API
                    System.out.println("URL do sprawdzenia: " + url);

                    // Przekaż zawartość JSON do metody isPhishing
                    boolean isPhishing = isPhishing(jsonString);
                    System.out.println("Is phishing: " + isPhishing);
                } else {
                    System.out.println("Nie udało się znaleźć URL w treści pliku JSON.");
                }
            } else {
                System.out.println("Błąd podczas wczytywania pliku JSON.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //program będzie wczytywał zawartość pliku SMS.json i przekazywał ją do metody isPhishing
    private static String readJsonFile(String filename) throws IOException {
        // Uzyskaj ścieżkę do pliku w katalogu resources
        Path path = Paths.get("src/main/resources", filename);

        // Sprawdź, czy plik istnieje
        if (Files.exists(path)) {
            // Wczytaj zawartość pliku do String
            return Files.readString(path);
        } else {
            System.out.println("Plik JSON nie istnieje.");
            return null;
        }
    }

    public static boolean isPhishing(String jsonString) {
        String url = extractURLFromJSON(jsonString);

        if (url != null && !url.isEmpty()) {
            return evaluatePhishing(url);
        }

        return false;
    }

    private static String extractURLFromJSON(String jsonString) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(jsonString);

            if (jsonNode.has("message")) {
                String message = jsonNode.get("message").asText();

                // Proba bezposredniego wyciagniecia URL z pola "message"
                Pattern pattern = Pattern.compile("(https?://\\S+)");
                Matcher matcher = pattern.matcher(message);

                if (matcher.find()) {
                    return matcher.group(1);
                }
            }

            // Jeżeli URL nie został znaleziony w polu "message", próbujemy tradycyjnej ekstrakcji
            if (jsonNode.has("url")) {
                return jsonNode.get("url").asText();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static boolean evaluatePhishing(String url) {
        try {
            URL riskApiEndpoint = new URL("https://webrisk.googleapis.com/v1eap1:evaluateUri?key=" + API_KEY);
            HttpURLConnection connection = (HttpURLConnection) riskApiEndpoint.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            // Tworzymy JSON zapytanie
            JSONObject jsonRequest = new JSONObject();
            jsonRequest.put("uri", url);
            jsonRequest.put("threatTypes", new JSONArray().put("MALWARE")); // Możemy dodawać więcej typów zagrożeń, jeśli potrzebujemy

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = jsonRequest.toString().getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            // Odczytujemy odpowiedź
            try (BufferedReader br = new BufferedReader(new InputStreamReader(connection.getInputStream(), "utf-8"))) {
                StringBuilder response = new StringBuilder();
                String responseLine = null;
                while ((responseLine = br.readLine()) != null) {
                    response.append(responseLine.trim());
                }

                // Analizujemy odpowiedź JSON
                JSONObject jsonResponse = new JSONObject(response.toString());
                JSONArray scores = jsonResponse.getJSONArray("scores");

                // Przyjmujemy, że interesuje nas tylko pierwszy wynik (MALWARE)
                JSONObject malwareScore = scores.getJSONObject(0);
                String confidenceLevel = malwareScore.getString("confidenceLevel");

                // Sprawdzamy, czy confidenceLevel wskazuje na ryzyko phishingu
                return confidenceLevel.equals("HIGH") || confidenceLevel.equals("HIGHER") || confidenceLevel.equals("VERY_HIGH") || confidenceLevel.equals("EXTREMELY_HIGH");
            }

        } catch (IOException | JSONException e) {
            e.printStackTrace();
        }

        return false;
    }

    private static String buildRequestBody(String url) {
        return String.format("{\"uri\": \"%s\", \"threatTypes\": [\"SOCIAL_ENGINEERING\", \"MALWARE\", \"UNWANTED_SOFTWARE\"], \"allowScan\": true}", url);
    }

    private static boolean analyzePhishingResponse(String responseBody) {
        // Implementacja analizy odpowiedzi od serwisu
        // Zwróć true, jeśli serwis ocenia URL jako phishing, w przeciwnym razie false
        return responseBody.contains("\"confidenceLevel\": \"HIGH\"");
    }
}

    // Konwersja tablicy na reprezentację JSON

//AIzaSyCGON0RcyFb-k2TfRfEBwTw5CS3g3sla4I