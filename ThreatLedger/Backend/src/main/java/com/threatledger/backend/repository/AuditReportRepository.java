package com.threatledger.backend.repository;

import com.threatledger.backend.entity.AuditReport;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuditReportRepository extends JpaRepository<AuditReport, Long> {

    Optional<AuditReport> findBySourceHash(String sourceHash);
}
