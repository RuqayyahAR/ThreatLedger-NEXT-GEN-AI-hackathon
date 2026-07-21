package com.threatledger.backend.repository;

import com.threatledger.backend.entity.ZkCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ZkCredentialRepository extends JpaRepository<ZkCredential, Long> {

    Optional<ZkCredential> findByCommitmentLeaf(String commitmentLeaf);
}
