package com.threatledger.backend.entity;

/**
 * Final deployment verdict emitted by the agentic auditor after reasoning
 * over all findings. GO == safe to push to mainnet.
 */
public enum DeploymentDecision {
    /** Agent reasoning in progress - never persisted in this state. */
    PENDING,
    /** Risk score below LOW threshold - clear to deploy. */
    GO,
    /** Minor issues - deploy with caveats, requires reviewer acknowledgement. */
    GO_WITH_WARNINGS,
    /** HIGH severity findings - block mainnet, allow testnet only. */
    NO_GO_TESTNET_ONLY,
    /** CRITICAL findings - block deployment and auto-emit to threat feed. */
    BLOCK_MAINNET
}
