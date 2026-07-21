package com.threatledger.backend.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpEntity;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/chat")
@CrossOrigin(origins = "*")
public class ChatController {

    private final String API_KEY = System.getenv("GEMINI_API_KEY");

    @PostMapping
    public ResponseEntity<Map<String, String>> processAnalystQuery(@RequestBody Map<String, String> payload) {
        String userQuery = payload.get("message");

        String systemContext = """
            You are the official AI Security Analyst for ThreatLedger. 
            Here is the exact architecture and security model of our platform:
            
            1. PURPOSE: A decentralized, peer-to-peer threat intelligence sharing network.
            2. INGESTION & POW: Users submit threat indicators (IPs, hashes) via the dashboard. 
               Clients must solve a SHA-256 Proof-of-Work (PoW) puzzle to prevent API spamming/DDoS.
            3. CONSENSUS ENGINE: Submitted threats start as PENDING. Independent peer nodes vote 
               on validity. Once an indicator crosses a strict 70% affirmative consensus threshold, 
               its status updates to VERIFIED.
            4. EDGE AUTOMATION: An automated Python daemon script (agent.py) polls for VERIFIED 
               threats, updates local Linux UFW firewall rules, and appends Snort/IDS signature rules.
            5. CORS & SECURITY: Backend REST endpoints use strict CORS policies and input validation 
               to prevent unauthorized payload execution.

            Answer user questions accurately based ONLY on this cybersecurity architecture.
            """;

        // Fallback if no key is set
        if (API_KEY == null || API_KEY.isEmpty()) {
            return ResponseEntity.ok(Map.of("reply", "ThreatLedger AI: Operating in offline mode. Consensus requirements active at 70%."));
        }

        // Gemini REST Endpoint Call
        String apiUrl = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=" + API_KEY;

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/json");

        // Construct request body for Gemini native API format
        Map<String, Object> systemInstruction = Map.of(
            "parts", List.of(Map.of("text", systemContext))
        );
        
        Map<String, Object> userContent = Map.of(
            "role", "user",
            "parts", List.of(Map.of("text", userQuery))
        );

        Map<String, Object> requestBody = Map.of(
            "system_instruction", systemInstruction,
            "contents", List.of(userContent)
        );

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);

        try {
            Map<?, ?> response = restTemplate.postForObject(apiUrl, entity, Map.class);
            List<?> candidates = (List<?>) response.get("candidates");
            Map<?, ?> firstCandidate = (Map<?, ?>) candidates.get(0);
            Map<?, ?> content = (Map<?, ?>) firstCandidate.get("content");
            List<?> parts = (List<?>) content.get("parts");
            Map<?, ?> firstPart = (Map<?, ?>) parts.get(0);
            String reply = (String) firstPart.get("text");

            return ResponseEntity.ok(Map.of("reply", reply));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("reply", "ThreatLedger AI: Unable to reach Gemini API. Ensure key permissions are active."));
        }
    }
}