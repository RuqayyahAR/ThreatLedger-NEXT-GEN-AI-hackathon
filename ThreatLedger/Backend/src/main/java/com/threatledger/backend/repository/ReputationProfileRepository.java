package com.threatledger.backend.repository;

import com.threatledger.backend.entity.ReputationProfile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ReputationProfileRepository extends JpaRepository<ReputationProfile, Long> {

    Optional<ReputationProfile> findByNodeId(String nodeId);

    Optional<ReputationProfile> findByZkAliasHash(String zkAliasHash);
}
