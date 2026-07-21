package com.threatledger.backend.repository;

import com.threatledger.backend.entity.AuditFinding;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditFindingRepository extends JpaRepository<AuditFinding, Long> {
}
