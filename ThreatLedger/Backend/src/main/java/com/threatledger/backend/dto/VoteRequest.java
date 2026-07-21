package com.threatledger.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Note: this shape isn't in the original data contract doc - I added it because
 * "Peer Validation & Consensus" needs *some* endpoint for other nodes to cast a vote.
 * Flag this to Ruqayyah/your teammates so it gets added to the shared contract too.
 */
public class VoteRequest {

    @NotBlank(message = "votingNode is required")
    private String votingNode;

    @NotNull(message = "voteValue is required (true = confirms malicious, false = false positive)")
    private Boolean voteValue;

    public String getVotingNode() {
        return votingNode;
    }

    public void setVotingNode(String votingNode) {
        this.votingNode = votingNode;
    }

    public Boolean getVoteValue() {
        return voteValue;
    }

    public void setVoteValue(Boolean voteValue) {
        this.voteValue = voteValue;
    }
}
