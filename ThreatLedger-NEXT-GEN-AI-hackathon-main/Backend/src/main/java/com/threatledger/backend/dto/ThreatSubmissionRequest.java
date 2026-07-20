package com.threatledger.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/**
 * Exactly matches Section 1 of the team's Data Exchange Contract:
 * { "indicatorValue", "indicatorType", "threatDescription", "submittedByNode", "proofOfWorkNonce" }
 */
public class ThreatSubmissionRequest {

    @NotBlank(message = "indicatorValue is required")
    private String indicatorValue;

    @NotBlank(message = "indicatorType is required")
    @Pattern(regexp = "IP|DOMAIN|HASH", message = "indicatorType must be IP, DOMAIN, or HASH")
    private String indicatorType;

    private String threatDescription;

    @NotBlank(message = "submittedByNode is required")
    private String submittedByNode;

    @NotNull(message = "proofOfWorkNonce is required")
    private Integer proofOfWorkNonce;

    public String getIndicatorValue() {
        return indicatorValue;
    }

    public void setIndicatorValue(String indicatorValue) {
        this.indicatorValue = indicatorValue;
    }

    public String getIndicatorType() {
        return indicatorType;
    }

    public void setIndicatorType(String indicatorType) {
        this.indicatorType = indicatorType;
    }

    public String getThreatDescription() {
        return threatDescription;
    }

    public void setThreatDescription(String threatDescription) {
        this.threatDescription = threatDescription;
    }

    public String getSubmittedByNode() {
        return submittedByNode;
    }

    public void setSubmittedByNode(String submittedByNode) {
        this.submittedByNode = submittedByNode;
    }

    public Integer getProofOfWorkNonce() {
        return proofOfWorkNonce;
    }

    public void setProofOfWorkNonce(Integer proofOfWorkNonce) {
        this.proofOfWorkNonce = proofOfWorkNonce;
    }
}
