package com.threatledger.backend.repository;

import com.threatledger.backend.entity.ZkProofRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ZkProofRecordRepository extends JpaRepository<ZkProofRecord, Long> {

    Optional<ZkProofRecord> findByNullifierHash(String nullifierHash);

    long countByZkAliasHashAndVerified(String zkAliasHash, boolean verified);
}
