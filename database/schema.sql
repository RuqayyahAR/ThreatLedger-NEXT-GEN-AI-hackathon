-- =========================================================================
-- ThreatLedger Database Initialization & Reference Schema
-- 
-- NOTE: Spring Boot JPA is configured to auto-generate these tables 
-- via hibernate.ddl-auto=update. This script serves as a baseline 
-- reference and manual setup fallback for the hackathon deployment.
-- =========================================================================

-- 1. Create the application database instance if it doesn't exist yet
CREATE DATABASE IF NOT EXISTS threatledger;
USE threatledger;

-- 2. Baseline structural preview of the Threats table for manual verification
-- (Mirrors the core data contract fields: indicatorValue, status, confidence)
CREATE TABLE IF NOT EXISTS threats (
    indicator_id INT AUTO_INCREMENT PRIMARY KEY,
    indicator_value VARCHAR(255) NOT NULL,
    indicator_type VARCHAR(50) NOT NULL,
    threat_description TEXT,
    submitted_by_node VARCHAR(100) NOT NULL,
    proof_of_work_nonce INT,
    consensus_status VARCHAR(50) DEFAULT 'PENDING',
    confidence_score DECIMAL(5,2) DEFAULT 0.00,
    total_votes_cast INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Baseline structural preview of the Peer Votes tracking table
CREATE TABLE IF NOT EXISTS votes (
    vote_id INT AUTO_INCREMENT PRIMARY KEY,
    indicator_id INT NOT NULL,
    voting_node VARCHAR(100) NOT NULL,
    vote_value BOOLEAN NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (indicator_id) REFERENCES threats(indicator_id) ON DELETE CASCADE,
    UNIQUE KEY uq_threat_voting_node (indicator_id, voting_node)
);

-- =========================================================================
-- TWIST FEATURE 1 — AI Smart Contract Auditor
-- (tables mirror the @Entity classes in com.threatledger.backend.entity)
-- =========================================================================

CREATE TABLE IF NOT EXISTS audit_reports (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    contract_name VARCHAR(255) NOT NULL,
    source_hash VARCHAR(64) NOT NULL,
    compiler_version VARCHAR(64),
    source_size_bytes INT,
    deployment_decision VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    risk_score DECIMAL(5,2) DEFAULT 0.0,
    summary TEXT,
    submitted_by_node VARCHAR(100),
    critical_count INT DEFAULT 0,
    high_count INT DEFAULT 0,
    medium_count INT DEFAULT 0,
    low_count INT DEFAULT 0,
    info_count INT DEFAULT 0,
    agentic_trace TEXT,
    linked_threat_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_audit_source_hash (source_hash),
    FOREIGN KEY (linked_threat_id) REFERENCES threats(indicator_id)
);

CREATE TABLE IF NOT EXISTS audit_findings (
    finding_id INT AUTO_INCREMENT PRIMARY KEY,
    report_id INT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    detector_id VARCHAR(64) NOT NULL,
    detector_label VARCHAR(255) NOT NULL,
    description VARCHAR(2000),
    location_hint VARCHAR(255),
    line_start INT,
    line_end INT,
    snippet VARCHAR(1000),
    recommendation VARCHAR(2000),
    ai_confidence DECIMAL(4,3),
    FOREIGN KEY (report_id) REFERENCES audit_reports(report_id) ON DELETE CASCADE
);

-- =========================================================================
-- TWIST FEATURE 2 — Decentralized ZK Reputation Protocol
-- =========================================================================

CREATE TABLE IF NOT EXISTS reputation_profiles (
    profile_id INT AUTO_INCREMENT PRIMARY KEY,
    node_id VARCHAR(100) UNIQUE,
    zk_alias_hash VARCHAR(64) NOT NULL UNIQUE,
    merkle_root VARCHAR(64) NOT NULL,
    credential_count INT DEFAULT 0,
    hackathon_wins INT DEFAULT 0,
    reputation_score DECIMAL(5,2) DEFAULT 0.00,
    tier VARCHAR(20) NOT NULL DEFAULT 'BRONZE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS zk_credentials (
    credential_id INT AUTO_INCREMENT PRIMARY KEY,
    profile_id INT NOT NULL,
    claim_type VARCHAR(50) NOT NULL,
    issuer_id VARCHAR(255) NOT NULL,
    commitment_leaf VARCHAR(64) NOT NULL UNIQUE,
    salt VARCHAR(64) NOT NULL,
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (profile_id) REFERENCES reputation_profiles(profile_id) ON DELETE CASCADE,
    UNIQUE KEY uq_profile_claim (profile_id, claim_type)
);

CREATE TABLE IF NOT EXISTS zk_proof_records (
    proof_id INT AUTO_INCREMENT PRIMARY KEY,
    profile_id INT,
    zk_alias_hash VARCHAR(64),
    claimed_type VARCHAR(50) NOT NULL,
    merkle_root VARCHAR(64) NOT NULL,
    nullifier_hash VARCHAR(64) NOT NULL UNIQUE,
    challenge VARCHAR(255) NOT NULL,
    response VARCHAR(255) NOT NULL,
    verifier_public_commit VARCHAR(255) NOT NULL,
    verified BOOLEAN NOT NULL,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verifier_id VARCHAR(255) NOT NULL
);
