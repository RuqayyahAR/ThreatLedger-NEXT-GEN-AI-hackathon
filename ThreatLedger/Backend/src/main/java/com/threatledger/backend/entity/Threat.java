package com.threatledger.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Field names deliberately mirror the "Data Structure Template" everyone agreed on
 * (indicatorValue, indicatorType, threatDescription, submittedByNode, proofOfWorkNonce,
 * indicatorId, consensusStatus, confidenceScore, totalVotesCast, createdAt) so Jackson
 * serializes this straight into the exact JSON shape the frontend and Python agent expect.
 */
@Entity
@Table(name = "threats")
public class Threat {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "indicator_id")
    private Long indicatorId;

    @Column(name = "indicator_value", nullable = false)
    private String indicatorValue;

    @Column(name = "indicator_type", nullable = false)
    private String indicatorType; // IP, DOMAIN, or HASH

    @Column(name = "threat_description", length = 1000)
    private String threatDescription;

    @Column(name = "submitted_by_node", nullable = false)
    private String submittedByNode;

    @Column(name = "proof_of_work_nonce")
    private Integer proofOfWorkNonce;

    @Enumerated(EnumType.STRING)
    @Column(name = "consensus_status", nullable = false)
    private ConsensusStatus consensusStatus = ConsensusStatus.PENDING;

    @Column(name = "confidence_score", nullable = false)
    private Double confidenceScore = 0.0;

    @Column(name = "total_votes_cast", nullable = false)
    private Integer totalVotesCast = 0;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public Threat() {
    }

    // ----- getters and setters -----

    public Long getIndicatorId() {
        return indicatorId;
    }

    public void setIndicatorId(Long indicatorId) {
        this.indicatorId = indicatorId;
    }

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

    public ConsensusStatus getConsensusStatus() {
        return consensusStatus;
    }

    public void setConsensusStatus(ConsensusStatus consensusStatus) {
        this.consensusStatus = consensusStatus;
    }

    public Double getConfidenceScore() {
        return confidenceScore;
    }

    public void setConfidenceScore(Double confidenceScore) {
        this.confidenceScore = confidenceScore;
    }

    public Integer getTotalVotesCast() {
        return totalVotesCast;
    }

    public void setTotalVotesCast(Integer totalVotesCast) {
        this.totalVotesCast = totalVotesCast;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
