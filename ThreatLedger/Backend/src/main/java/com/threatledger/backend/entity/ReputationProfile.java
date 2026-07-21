package com.threatledger.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A developer's ZK reputation profile.
 *
 * Privacy model: rather than exposing identity material, the profile binds
 * to the existing {@link Node#nodeId} (a transparent, already-pseudonymous
 * handle) AND maintains a separate ZK-side nullifier handle (zkAliasHash).
 * The profile stores:
 *   - a Merkle root over all issued {@link ZkCredential} commitment leaves
 *   - aggregate counters (total credentials, hackathon wins, etc.)
 *   - recommendation score in [0,100]
 *
 * The linkage between submitted threat / audit reports and the profile is
 * optional - profile holders with verified credentials receive a reputation
 * multiplier when their submissions are scored for consensus.
 */
@Entity
@Table(name = "reputation_profiles")
public class ReputationProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "profile_id")
    private Long profileId;

    @Column(name = "node_id", unique = true)
    private String nodeId; // optional FK to existing nodes; populated if the developer runs a peer node

    @Column(name = "zk_alias_hash", nullable = false, unique = true)
    private String zkAliasHash; // hex H(secretIdentityMaterial || serverSalt) - never reveals the PII

    @Column(name = "merkle_root", nullable = false)
    private String merkleRoot; // hex SHA-256 root recomputed every credential change

    @Column(name = "credential_count", nullable = false)
    private Integer credentialCount = 0;

    @Column(name = "hackathon_wins", nullable = false)
    private Integer hackathonWins = 0;

    @Column(name = "reputation_score", nullable = false)
    private Double reputationScore = 50.0; // initialized to neutral; [0,100]

    @Column(name = "tier", nullable = false)
    private String tier = "BRONZE"; // BRONZE / SILVER / GOLD / PLATINUM - derived from score

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @OneToMany(mappedBy = "profile", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    private List<ZkCredential> credentials = new ArrayList<>();

    public ReputationProfile() {
    }

    public Long getProfileId() {
        return profileId;
    }

    public void setProfileId(Long profileId) {
        this.profileId = profileId;
    }

    public String getNodeId() {
        return nodeId;
    }

    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }

    public String getZkAliasHash() {
        return zkAliasHash;
    }

    public void setZkAliasHash(String zkAliasHash) {
        this.zkAliasHash = zkAliasHash;
    }

    public String getMerkleRoot() {
        return merkleRoot;
    }

    public void setMerkleRoot(String merkleRoot) {
        this.merkleRoot = merkleRoot;
    }

    public Integer getCredentialCount() {
        return credentialCount;
    }

    public void setCredentialCount(Integer credentialCount) {
        this.credentialCount = credentialCount;
    }

    public Integer getHackathonWins() {
        return hackathonWins;
    }

    public void setHackathonWins(Integer hackathonWins) {
        this.hackathonWins = hackathonWins;
    }

    public Double getReputationScore() {
        return reputationScore;
    }

    public void setReputationScore(Double reputationScore) {
        this.reputationScore = reputationScore;
    }

    public String getTier() {
        return tier;
    }

    public void setTier(String tier) {
        this.tier = tier;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }

    public List<ZkCredential> getCredentials() {
        return credentials;
    }

    public void setCredentials(List<ZkCredential> credentials) {
        this.credentials = credentials;
    }
}
