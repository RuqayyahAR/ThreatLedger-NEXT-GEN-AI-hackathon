package com.threatledger.backend.dto;

import java.time.Instant;
import java.util.List;

public class ChatResponse {

    private String response;
    private String language;
    private String sessionId;
    private Instant timestamp;
    private List<String> suggestedQuestions;
    private String threatContext;

    public ChatResponse() {
        this.timestamp = Instant.now();
    }

    public ChatResponse(String response, String language, String sessionId) {
        this.response = response;
        this.language = language;
        this.sessionId = sessionId;
        this.timestamp = Instant.now();
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public List<String> getSuggestedQuestions() {
        return suggestedQuestions;
    }

    public void setSuggestedQuestions(List<String> suggestedQuestions) {
        this.suggestedQuestions = suggestedQuestions;
    }

    public String getThreatContext() {
        return threatContext;
    }

    public void setThreatContext(String threatContext) {
        this.threatContext = threatContext;
    }
}