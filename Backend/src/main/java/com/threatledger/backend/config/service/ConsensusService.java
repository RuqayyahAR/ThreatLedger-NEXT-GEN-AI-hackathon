package com.threatledger.backend.service;

import com.threatledger.backend.entity.ConsensusStatus;
import com.threatledger.backend.entity.Threat;
import com.threatledger.backend.repository.VoteRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * "Consensus Engine" from the doc: recalculates confidenceScore and consensusStatus
 * every time a new vote comes in.
 *
 * Assumption (not spelled out in the contract doc, so flag it to your team): we also
 * require a minimum number of votes before flipping to VERIFIED/REJECTED, so a single
 * vote can't instantly verify a threat. Tune MIN_VOTES_REQUIRED for your demo.
 */
@Service
public class ConsensusService {

    @Value("${threatledger.consensus.min-votes:3}")
    private int minVotesRequired;

    @Value("${threatledger.consensus.verify-threshold:70.0}")
    private double verifyThreshold;

    @Value("${threatledger.consensus.reject-threshold:30.0}")
    private double rejectThreshold;

    private final VoteRepository voteRepository;

    public ConsensusService(VoteRepository voteRepository) {
        this.voteRepository = voteRepository;
    }

    /** Recomputes confidenceScore/totalVotesCast/consensusStatus for a threat and mutates it in place. */
    public void recalculate(Threat threat) {
        long total = voteRepository.countByThreat_IndicatorId(threat.getIndicatorId());
        long positive = voteRepository.countByThreat_IndicatorIdAndVoteValue(threat.getIndicatorId(), true);

        double confidence = total == 0 ? 0.0 : (positive * 100.0) / total;
        // round to 1 decimal place, e.g. 88.5 like in the contract example
        confidence = Math.round(confidence * 10.0) / 10.0;

        threat.setTotalVotesCast((int) total);
        threat.setConfidenceScore(confidence);

        if (total >= minVotesRequired && confidence >= verifyThreshold) {
            threat.setConsensusStatus(ConsensusStatus.VERIFIED);
        } else if (total >= minVotesRequired && confidence <= rejectThreshold) {
            threat.setConsensusStatus(ConsensusStatus.REJECTED);
        } else {
            threat.setConsensusStatus(ConsensusStatus.PENDING);
        }
    }
}
