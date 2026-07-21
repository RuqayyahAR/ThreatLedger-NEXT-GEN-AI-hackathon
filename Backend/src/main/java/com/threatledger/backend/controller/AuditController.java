package com.threatledger.backend.controller;

import com.threatledger.backend.dto.AuditRequest;
import com.threatledger.backend.dto.AuditResponse;
import com.threatledger.backend.entity.AuditReport;
import com.threatledger.backend.service.SolidityAuditorService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * AI agentic Solidity auditor endpoints.
 *
 *   POST /api/audit                  -> run the agentic loop on a contract
 *   GET  /api/audit                  -> list recent audit reports
 *   GET  /api/audit/{reportId}       -> fetch a specific report
 *
 * Doesn't touch or modify any baseline endpoint. The auditor's only
 * baseline touchpoint is the optional auto-escalation of CRITICAL findings
 * into the existing threat feed (performed inside the service).
 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final SolidityAuditorService auditorService;

    public AuditController(SolidityAuditorService auditorService) {
        this.auditorService = auditorService;
    }

    @PostMapping
    public ResponseEntity<AuditResponse> runAudit(@Valid @RequestBody AuditRequest request) {
        boolean escalate = request.getEscalateToThreatFeed() == null || request.getEscalateToThreatFeed();
        AuditReport report = auditorService.audit(
            request.getContractName(),
            request.getSoliditySource(),
            request.getCompilerVersion(),
            request.getSubmittedByNode(),
            escalate
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(AuditResponse.fromEntity(report));
    }

    @GetMapping
    public ResponseEntity<List<AuditResponse>> listReports() {
        List<AuditResponse> all = auditorService.listReports().stream()
            .map(AuditResponse::fromEntity).toList();
        return ResponseEntity.ok(all);
    }

    @GetMapping("/{reportId}")
    public ResponseEntity<AuditResponse> getReport(@PathVariable Long reportId) {
        return ResponseEntity.ok(AuditResponse.fromEntity(auditorService.getReport(reportId)));
    }
}
