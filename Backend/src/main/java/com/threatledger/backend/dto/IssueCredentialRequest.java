package com.threatledger.backend.dto;

import com.threatledger.backend.entity.ClaimType;
import jakarta.validation.constraints.NotBlank;

public class IssueCredentialRequest {

    private Long profileId;
    private ClaimType claimType;
    @NotBlank(message = "issuerId is required")
    private String issuerId;
    @NotBlank(message = "secretForCommitment is required to derive the Pedersen-style leaf")
    private String secretForCommitment;

    public Long getProfileId() { return profileId; }
    public void setProfileId(Long p) { this.profileId = p; }
    public ClaimType getClaimType() { return claimType; }
    public void setClaimType(ClaimType c) { this.claimType = c; }
    public String getIssuerId() { return issuerId; }
    public void setIssuerId(String i) { this.issuerId = i; }
    public String getSecretForCommitment() { return secretForCommitment; }
    public void setSecretForCommitment(String s) { this.secretForCommitment = s; }
}
