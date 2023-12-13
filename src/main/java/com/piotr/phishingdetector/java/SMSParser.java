package com.piotr.phishingdetector.java;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SMSParser {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static List<String> extractMessagesFromJson(List<String> jsonMessages) {
        List<String> messages = new ArrayList<>();

        for (String jsonMessage : jsonMessages) {
            String message = parseMessageFromJson(jsonMessage);

            if (message != null) {
                messages.add(message);
            }
        }

        return messages;
    }

    private static String parseMessageFromJson(String jsonMessage) {
        try {
            JsonNode rootNode = objectMapper.readTree(jsonMessage);
            JsonNode messageNode = rootNode.get("message");

            if (messageNode != null) {
                return messageNode.asText();
            }
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        return null;
    }

    public static String extractURLFromMessage(String message) {
        String urlPattern = "(?i)\\b((?:https?|ftp):\\/\\/\\S+)";
        Pattern pattern = Pattern.compile(urlPattern);
        Matcher matcher = pattern.matcher(message);

        if (matcher.find()) {
            return matcher.group();
        }
        return null;
    }
}