package com.threatledger.backend.dto;

import com.threatledger.backend.entity.ReputationProfile;

import java.time.Instant;
import java.util.List;

public class ReputationResponse {

    private Long profileId;
    private String nodeId;
    private String zkAliasHash;
    private String merkleRoot;
    private Integer credentialCount;
    private Integer hackathonWins;
    private Double reputationScore;
    private String tier;
    private Instant createdAt;
    private Instant updatedAt;
    private List<String> credentialLeaves; // commitment leaves only - no PII

    public static ReputationResponse fromEntity(ReputationProfile p) {
        ReputationResponse r = new ReputationResponse();
        r.profileId = p.getProfileId();
        r.nodeId = p.getNodeId();
        r.zkAliasHash = p.getZkAliasHash();
        r.merkleRoot = p.getMerkleRoot();
        r.credentialCount = p.getCredentialCount();
        r.hackathonWins = p.getHackathonWins();
        r.reputationScore = p.getReputationScore();
        r.tier = p.getTier();
        r.createdAt = p.getCreatedAt();
        r.updatedAt = p.getUpdatedAt();
        r.credentialLeaves = p.getCredentials().stream()
            .map(c -> c.getCommitmentLeaf().substring(0, 16) + "...") // truncated leaves - no PII leaks
            .toList();
        return r;
    }

    public Long getProfileId() { return profileId; }
    public String getNodeId() { return nodeId; }
    public String getZkAliasHash() { return zkAliasHash; }
    public String getMerkleRoot() { return merkleRoot; }
    public Integer getCredentialCount() { return credentialCount; }
    public Integer getHackathonWins() { return hackathonWins; }
    public Double getReputationScore() { return reputationScore; }
    public String getTier() { return tier; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public List<String> getCredentialLeaves() { return credentialLeaves; }
}
