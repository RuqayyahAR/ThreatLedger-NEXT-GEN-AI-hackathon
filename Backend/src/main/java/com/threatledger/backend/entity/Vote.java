package com.threatledger.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(
    name = "votes",
    uniqueConstraints = @UniqueConstraint(
        name = "uq_threat_voting_node",
        columnNames = {"indicator_id", "voting_node"}
    )
) // a node can only vote once per threat
public class Vote {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "vote_id")
    private Long voteId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "indicator_id", nullable = false)
    private Threat threat;

    @Column(name = "voting_node", nullable = false)
    private String votingNode;

    // true = "I also see this as malicious" (positive vote), false = "looks like a false positive"
    @Column(name = "vote_value", nullable = false)
    private boolean voteValue;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public Vote() {
    }

    public Long getVoteId() {
        return voteId;
    }

    public void setVoteId(Long voteId) {
        this.voteId = voteId;
    }

    public Threat getThreat() {
        return threat;
    }

    public void setThreat(Threat threat) {
        this.threat = threat;
    }

    public String getVotingNode() {
        return votingNode;
    }

    public void setVotingNode(String votingNode) {
        this.votingNode = votingNode;
    }

    public boolean isVoteValue() {
        return voteValue;
    }

    public void setVoteValue(boolean voteValue) {
        this.voteValue = voteValue;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
