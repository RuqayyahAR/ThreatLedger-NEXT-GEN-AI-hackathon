package com.threatledger.backend.repository;

import com.threatledger.backend.entity.ConsensusStatus;
import com.threatledger.backend.entity.Threat;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ThreatRepository extends JpaRepository<Threat, Long> {

    // Used by Member 3's Python agent: GET /api/threats?status=VERIFIED
    List<Threat> findByConsensusStatusOrderByCreatedAtDesc(ConsensusStatus status);

    List<Threat> findAllByOrderByCreatedAtDesc();
}
