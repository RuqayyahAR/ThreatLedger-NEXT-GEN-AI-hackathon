package com.threatledger.backend.repository;

import com.threatledger.backend.entity.Vote;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VoteRepository extends JpaRepository<Vote, Long> {

    boolean existsByThreat_IndicatorIdAndVotingNode(Long indicatorId, String votingNode);

    long countByThreat_IndicatorId(Long indicatorId);

    long countByThreat_IndicatorIdAndVoteValue(Long indicatorId, boolean voteValue);
}
