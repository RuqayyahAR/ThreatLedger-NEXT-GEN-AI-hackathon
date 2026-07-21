package com.threatledger.backend.dto;

import jakarta.validation.constraints.NotBlank;

public class GenerateProofRequest {
    private Long profileId;
    @NotBlank
    private String secretHex; // hex-encoded secret exponent of the prover's identity
    @NotBlank
    private String transcript; // public statement being proven; Fiat-Shamir hashed
    @NotBlank
    private String verifierId; // which peer / auditor is asking

    public Long getProfileId() { return profileId; }
    public void setProfileId(Long p) { this.profileId = p; }
    public String getSecretHex() { return secretHex; }
    public void setSecretHex(String s) { this.secretHex = s; }
    public String getTranscript() { return transcript; }
    public void setTranscript(String t) { this.transcript = t; }
    public String getVerifierId() { return verifierId; }
    public void setVerifierId(String v) { this.verifierId = v; }
}
