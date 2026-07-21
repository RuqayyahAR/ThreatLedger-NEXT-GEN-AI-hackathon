package com.threatledger.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Audit trail for every ZK proof verification performed against the
 * reputation protocol. Persisting these lets the protocol publish verifiable
 * "this developer proved they hold a hackathon-winner credential at time T,
 * without revealing which hackathon or which developer" events to the
 * dashboard - useful both for the jury pitch and for forensic transparency.
 */
@Entity
@Table(name = "zk_proof_records")
public class ZkProofRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "proof_id")
    private Long proofId;

    @Column(name = "profile_id")
    private Long profileId; // optional - null if prover chose fully anonymous verification

    @Column(name = "zk_alias_hash")
    private String zkAliasHash; // pseudonymous identifier from the profile

    @Enumerated(EnumType.STRING)
    @Column(name = "claimed_type", nullable = false)
    private ClaimType claimedType;

    @Column(name = "merkle_root", nullable = false)
    private String merkleRoot; // root the prover committed to

    @Column(name = "nullifier_hash", nullable = false, unique = true)
    private String nullifierHash; // double-H so a credential cannot be double-proven anonymously

    @Column(name = "challenge", nullable = false)
    private String challenge; // hex random challenge issued by the verifier (Fiat-Shamir derived)

    @Column(name = "response", nullable = false)
    private String response; // hex prover response = x + challenge * secretWitness (Schnorr-style)

    @Column(name = "verifier_public_commit", nullable = false)
    private String verifierPublicCommit; // hex Y = g^x mod p the prover committed to in round 1

    @Column(name = "verified", nullable = false)
    private boolean verified;

    @Column(name = "verified_at", nullable = false, updatable = false)
    private Instant verifiedAt = Instant.now();

    @Column(name = "verifier_id", nullable = false)
    private String verifierId; // which peer / auditor called the verifier

    public ZkProofRecord() {
    }

    public Long getProofId() {
        return proofId;
    }

    public void setProofId(Long proofId) {
        this.proofId = proofId;
    }

    public Long getProfileId() {
        return profileId;
    }

    public void setProfileId(Long profileId) {
        this.profileId = profileId;
    }

    public String getZkAliasHash() {
        return zkAliasHash;
    }

    public void setZkAliasHash(String zkAliasHash) {
        this.zkAliasHash = zkAliasHash;
    }

    public ClaimType getClaimedType() {
        return claimedType;
    }

    public void setClaimedType(ClaimType claimedType) {
        this.claimedType = claimedType;
    }

    public String getMerkleRoot() {
        return merkleRoot;
    }

    public void setMerkleRoot(String merkleRoot) {
        this.merkleRoot = merkleRoot;
    }

    public String getNullifierHash() {
        return nullifierHash;
    }

    public void setNullifierHash(String nullifierHash) {
        this.nullifierHash = nullifierHash;
    }

    public String getChallenge() {
        return challenge;
    }

    public void setChallenge(String challenge) {
        this.challenge = challenge;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public String getVerifierPublicCommit() {
        return verifierPublicCommit;
    }

    public void setVerifierPublicCommit(String verifierPublicCommit) {
        this.verifierPublicCommit = verifierPublicCommit;
    }

    public boolean isVerified() {
        return verified;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public Instant getVerifiedAt() {
        return verifiedAt;
    }

    public void setVerifiedAt(Instant verifiedAt) {
        this.verifiedAt = verifiedAt;
    }

    public String getVerifierId() {
        return verifierId;
    }

    public void setVerifierId(String verifierId) {
        this.verifierId = verifierId;
    }
}
