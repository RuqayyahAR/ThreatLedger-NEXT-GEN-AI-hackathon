package com.threatledger.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Issued credential bound to a developer's ZK reputation profile.
 *
 * Privacy model: the protocol stores only the SHA-256 commitment leaf -
 * `H(credentialSecret || profileSalt || issuerId || claimType)` - which can
 * be inserted into the profile's Merkle tree. The plaintext claim is never
 * persisted and the issuer only ever reveals thesalted commitment, so a
 * verifier learns "this developer holds an unforgeable credential of type
 * X issued by Y" - nothing more.
 *
 * The corresponding ZK proof lives entirely in the request/response flow and
 * is recorded via {@link com.threatledger.backend.entity.ZkProofRecord}.
 */
@Entity
@Table(
    name = "zk_credentials",
    uniqueConstraints = @UniqueConstraint(
        name = "uq_profile_claim",
        columnNames = {"profile_id", "claim_type"}
    )
)
public class ZkCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "credential_id")
    private Long credentialId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "profile_id", nullable = false)
    private ReputationProfile profile;

    @Enumerated(EnumType.STRING)
    @Column(name = "claim_type", nullable = false)
    private ClaimType claimType;

    @Column(name = "issuer_id", nullable = false)
    private String issuerId; // e.g. "NEXT-GEN-AI-HACKATHON-2026"

    @Column(name = "commitment_leaf", nullable = false, unique = true)
    private String commitmentLeaf; // hex SHA-256 leaf used in the Merkle tree

    @Column(name = "salt", nullable = false)
    private String salt; // per-credential random salt (hex)

    @Column(name = "issued_at", nullable = false, updatable = false)
    private Instant issuedAt = Instant.now();

    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    public ZkCredential() {
    }

    public Long getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(Long credentialId) {
        this.credentialId = credentialId;
    }

    public ReputationProfile getProfile() {
        return profile;
    }

    public void setProfile(ReputationProfile profile) {
        this.profile = profile;
    }

    public ClaimType getClaimType() {
        return claimType;
    }

    public void setClaimType(ClaimType claimType) {
        this.claimType = claimType;
    }

    public String getIssuerId() {
        return issuerId;
    }

    public void setIssuerId(String issuerId) {
        this.issuerId = issuerId;
    }

    public String getCommitmentLeaf() {
        return commitmentLeaf;
    }

    public void setCommitmentLeaf(String commitmentLeaf) {
        this.commitmentLeaf = commitmentLeaf;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }
}
