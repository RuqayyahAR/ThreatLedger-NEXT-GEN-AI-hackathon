package com.threatledger.backend.dto;

import jakarta.validation.constraints.NotBlank;

public class VerifyProofRequest {
    private Long proofId;
    @NotBlank
    private String transcript; // must match transcript used at generation time

    public Long getProofId() { return proofId; }
    public void setProofId(Long p) { this.proofId = p; }
    public String getTranscript() { return transcript; }
    public void setTranscript(String t) { this.transcript = t; }
}
