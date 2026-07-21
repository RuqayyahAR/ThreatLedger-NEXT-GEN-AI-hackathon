package com.threatledger.backend.entity;

/**
 * Type of verifiable credential issued by a trusted authority (hackathon
 * organizer, employer, certification body) into a developer's ZK reputation
 * profile. The actual claim value is never stored in plaintext - only the
 * SHA-256 Pedersen-style commitment leaf hash is persisted.
 */
public enum ClaimType {
    HACKATHON_PARTICIPANT,
    HACKATHON_WINNER,
    HACKATHON_FINALIST,
    VERIFIED_DEVELOPER_ID,
    K_Y_C_VERIFIED,
    CODE_REVIEW_SIGNOFF,
    SECURITY_AUDIT_ISSUED
}
