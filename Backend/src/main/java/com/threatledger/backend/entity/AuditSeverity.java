package com.threatledger.backend.entity;

/**
 * Severity classification for findings produced by the AI Solidity auditor.
 * Ordering mirrors business priority - CRITICAL findings should block
 * mainnet deployment entirely, LOW findings are informational.
 */
public enum AuditSeverity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
}
