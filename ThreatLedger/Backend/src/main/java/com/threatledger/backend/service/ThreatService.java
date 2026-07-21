package com.threatledger.backend.service;

import com.threatledger.backend.dto.ThreatResponse;
import com.threatledger.backend.dto.ThreatSubmissionRequest;
import com.threatledger.backend.dto.VoteRequest;
import com.threatledger.backend.entity.ConsensusStatus;
import com.threatledger.backend.entity.Node;
import com.threatledger.backend.entity.Threat;
import com.threatledger.backend.entity.Vote;
import com.threatledger.backend.repository.NodeRepository;
import com.threatledger.backend.repository.ThreatRepository;
import com.threatledger.backend.repository.VoteRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class ThreatService {

    private final ThreatRepository threatRepository;
    private final VoteRepository voteRepository;
    private final NodeRepository nodeRepository;
    private final ProofOfWorkService proofOfWorkService;
    private final ConsensusService consensusService;

    public ThreatService(ThreatRepository threatRepository,
                          VoteRepository voteRepository,
                          NodeRepository nodeRepository,
                          ProofOfWorkService proofOfWorkService,
                          ConsensusService consensusService) {
        this.threatRepository = threatRepository;
        this.voteRepository = voteRepository;
        this.nodeRepository = nodeRepository;
        this.proofOfWorkService = proofOfWorkService;
        this.consensusService = consensusService;
    }

    @Transactional
    public ThreatResponse submitThreat(ThreatSubmissionRequest request) {
        if (!proofOfWorkService.isValid(request.getIndicatorValue(), request.getProofOfWorkNonce())) {
            throw new IllegalArgumentException(
                "Invalid proof-of-work nonce for this indicatorValue (need "
                    + proofOfWorkService.getDifficulty() + " leading zero hex chars in the SHA-256 hash)."
            );
        }

        // make sure the submitting node is registered (auto-register on first submission)
        nodeRepository.findById(request.getSubmittedByNode())
            .orElseGet(() -> nodeRepository.save(new Node(request.getSubmittedByNode())));

        Threat threat = new Threat();
        threat.setIndicatorValue(request.getIndicatorValue());
        threat.setIndicatorType(request.getIndicatorType());
        threat.setThreatDescription(request.getThreatDescription());
        threat.setSubmittedByNode(request.getSubmittedByNode());
        threat.setProofOfWorkNonce(request.getProofOfWorkNonce());
        threat.setConsensusStatus(ConsensusStatus.PENDING);
        threat.setConfidenceScore(0.0);
        threat.setTotalVotesCast(0);

        Threat saved = threatRepository.save(threat);
        return ThreatResponse.fromEntity(saved);
    }

    public List<ThreatResponse> getAllThreats(ConsensusStatus statusFilter) {
        List<Threat> threats = statusFilter == null
            ? threatRepository.findAllByOrderByCreatedAtDesc()
            : threatRepository.findByConsensusStatusOrderByCreatedAtDesc(statusFilter);

        return threats.stream().map(ThreatResponse::fromEntity).toList();
    }

    public ThreatResponse getThreatById(Long indicatorId) {
        Threat threat = threatRepository.findById(indicatorId)
            .orElseThrow(() -> new IllegalArgumentException("No threat found with indicatorId " + indicatorId));
        return ThreatResponse.fromEntity(threat);
    }

    @Transactional
    public ThreatResponse castVote(Long indicatorId, VoteRequest request) {
        Threat threat = threatRepository.findById(indicatorId)
            .orElseThrow(() -> new IllegalArgumentException("No threat found with indicatorId " + indicatorId));

        if (voteRepository.existsByThreat_IndicatorIdAndVotingNode(indicatorId, request.getVotingNode())) {
            throw new IllegalArgumentException(
                "Node " + request.getVotingNode() + " has already voted on threat " + indicatorId
            );
        }

        nodeRepository.findById(request.getVotingNode())
            .orElseGet(() -> nodeRepository.save(new Node(request.getVotingNode())));

        Vote vote = new Vote();
        vote.setThreat(threat);
        vote.setVotingNode(request.getVotingNode());
        vote.setVoteValue(request.getVoteValue());
        voteRepository.save(vote);

        consensusService.recalculate(threat);
        Threat updated = threatRepository.save(threat);

        return ThreatResponse.fromEntity(updated);
    }
}
