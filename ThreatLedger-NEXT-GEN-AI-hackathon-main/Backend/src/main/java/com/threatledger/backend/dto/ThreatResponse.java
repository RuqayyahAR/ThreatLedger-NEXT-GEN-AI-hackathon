package com.threatledger.backend.dto;

import com.threatledger.backend.entity.Threat;

import java.time.Instant;

/**
 * Exactly matches Section 2 of the Data Exchange Contract - this is what the JS dashboard
 * renders and what the Python agent polls & filters on consensusStatus == "VERIFIED".
 */
public class ThreatResponse {

    private Long indicatorId;
    private String indicatorValue;
    private String indicatorType;
    private String threatDescription;
    private String submittedByNode;
    private String consensusStatus;
    private Double confidenceScore;
    private Integer totalVotesCast;
    private Instant createdAt;

    public static ThreatResponse fromEntity(Threat t) {
        ThreatResponse r = new ThreatResponse();
        r.indicatorId = t.getIndicatorId();
        r.indicatorValue = t.getIndicatorValue();
        r.indicatorType = t.getIndicatorType();
        r.threatDescription = t.getThreatDescription();
        r.submittedByNode = t.getSubmittedByNode();
        r.consensusStatus = t.getConsensusStatus().name();
        r.confidenceScore = t.getConfidenceScore();
        r.totalVotesCast = t.getTotalVotesCast();
        r.createdAt = t.getCreatedAt();
        return r;
    }

    public Long getIndicatorId() {
        return indicatorId;
    }

    public String getIndicatorValue() {
        return indicatorValue;
    }

    public String getIndicatorType() {
        return indicatorType;
    }

    public String getThreatDescription() {
        return threatDescription;
    }

    public String getSubmittedByNode() {
        return submittedByNode;
    }

    public String getConsensusStatus() {
        return consensusStatus;
    }

    public Double getConfidenceScore() {
        return confidenceScore;
    }

    public Integer getTotalVotesCast() {
        return totalVotesCast;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
