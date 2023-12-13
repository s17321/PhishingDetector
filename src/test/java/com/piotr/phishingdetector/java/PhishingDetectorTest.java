package com.piotr.phishingdetector.java;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PhishingDetectorTest {

    @Test
    void testIsPhishing() {
        String phishingUrl = "https://www.phishing-example.com";
        String nonPhishingUrl = "https://www.non-phishing-example.com";

        assertTrue(PhishingDetector.isPhishing(phishingUrl), "Expected phishing URL");
        assertFalse(PhishingDetector.isPhishing(nonPhishingUrl), "Expected non-phishing URL");
    }
}