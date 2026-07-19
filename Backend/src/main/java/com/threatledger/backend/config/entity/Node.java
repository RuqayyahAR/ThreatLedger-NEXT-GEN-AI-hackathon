package com.threatledger.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "nodes")
public class Node {

    @Id
    @Column(name = "node_id", nullable = false, unique = true)
    private String nodeId; // e.g. "NODE-NODE-772A" - matches submittedByNode in the contract

    @Column(name = "token_balance")
    private Integer tokenBalance = 100; // starting stake balance, spent on proof-of-work submissions

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public Node() {
    }

    public Node(String nodeId) {
        this.nodeId = nodeId;
    }

    public String getNodeId() {
        return nodeId;
    }

    public void setNodeId(String nodeId) {
        this.nodeId = nodeId;
    }

    public Integer getTokenBalance() {
        return tokenBalance;
    }

    public void setTokenBalance(Integer tokenBalance) {
        this.tokenBalance = tokenBalance;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
