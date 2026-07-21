package com.threatledger.backend.dto;

import jakarta.validation.constraints.NotBlank;

public class CreateProfileRequest {

    @NotBlank(message = "secretIdentityMaterial is required (will be hashed, never stored)")
    private String secretIdentityMaterial;

    private String nodeId; // optional - links to existing nodes for consensus weight bump

    public String getSecretIdentityMaterial() { return secretIdentityMaterial; }
    public void setSecretIdentityMaterial(String s) { this.secretIdentityMaterial = s; }
    public String getNodeId() { return nodeId; }
    public void setNodeId(String n) { this.nodeId = n; }
}
