package com.threatledger.backend.entity;

/**
 * Matches the consensusStatus field in the team's JSON data contract.
 * PENDING   -> just submitted, not enough votes yet
 * VERIFIED  -> reached the positive-vote threshold, Python agent should block it
 * REJECTED  -> peers flagged it as false positive / spam
 */
public enum ConsensusStatus {
    PENDING,
    VERIFIED,
    REJECTED
}
