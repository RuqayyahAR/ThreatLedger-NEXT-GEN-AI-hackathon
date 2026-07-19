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
    consensus_status VARCHAR(50) DEFAULT 'PENDING',
    confidence_score DECIMAL(5,2) DEFAULT 0.00,
    total_votes_cast INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Baseline structural preview of the Peer Votes tracking table
CREATE TABLE IF NOT EXISTS votes (
    vote_id INT AUTO_INCREMENT PRIMARY KEY,
    threat_id INT NOT NULL,
    voting_node VARCHAR(100) NOT NULL,
    vote_value BOOLEAN NOT NULL,
    voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (threat_id) REFERENCES threats(indicator_id) ON DELETE CASCADE
);
