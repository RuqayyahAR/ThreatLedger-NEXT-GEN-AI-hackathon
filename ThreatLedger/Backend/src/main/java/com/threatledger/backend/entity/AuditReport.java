package com.threatledger.backend.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Result of running the AI Solidity auditor against one contract source bundle.
 *
 * A report is "mainnet-ready" only when deploymentDecision == GO. The agent
 * escalates CRITICAL findings into the existing threat feed by auto-emitting
 * a {@link Threat} row tagged with indicatorType=HASH (the contract bytecode
 * hash) - wiring the twist into the baseline consensus pipeline without
 * breaking it.
 */
@Entity
@Table(name = "audit_reports")
public class AuditReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "report_id")
    private Long reportId;

    @Column(name = "contract_name", nullable = false)
    private String contractName;

    @Column(name = "source_hash", nullable = false, unique = true)
    private String sourceHash; // SHA-256 of normalized source - dedup key

    @Column(name = "compiler_version")
    private String compilerVersion;

    @Column(name = "source_size_bytes")
    private Integer sourceSizeBytes;

    @Enumerated(EnumType.STRING)
    @Column(name = "deployment_decision", nullable = false)
    private DeploymentDecision deploymentDecision = DeploymentDecision.PENDING;

    @Column(name = "risk_score")
    private Double riskScore; // 0.0 (safe) - 100.0 (critical), drives decision

    @Column(name = "summary", length = 4000)
    private String summary; // AI-generated natural-language executive summary

    @Column(name = "submitted_by_node")
    private String submittedByNode; // optional - links to a verified reputation profile

    @Column(name = "critical_count", nullable = false)
    private Integer criticalCount = 0;

    @Column(name = "high_count", nullable = false)
    private Integer highCount = 0;

    @Column(name = "medium_count", nullable = false)
    private Integer mediumCount = 0;

    @Column(name = "low_count", nullable = false)
    private Integer lowCount = 0;

    @Column(name = "info_count", nullable = false)
    private Integer infoCount = 0;

    @Column(name = "agentic_trace", length = 4000)
    private String agenticTrace; // multi-stage reasoning log for transparency/jury pitch

    @Column(name = "linked_threat_id")
    private Long linkedThreatId; // if the agent auto-published a threat row, the FK

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @OneToMany(mappedBy = "report", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @OrderBy("severity ASC")
    private List<AuditFinding> findings = new ArrayList<>();

    public AuditReport() {
    }

    public Long getReportId() {
        return reportId;
    }

    public void setReportId(Long reportId) {
        this.reportId = reportId;
    }

    public String getContractName() {
        return contractName;
    }

    public void setContractName(String contractName) {
        this.contractName = contractName;
    }

    public String getSourceHash() {
        return sourceHash;
    }

    public void setSourceHash(String sourceHash) {
        this.sourceHash = sourceHash;
    }

    public String getCompilerVersion() {
        return compilerVersion;
    }

    public void setCompilerVersion(String compilerVersion) {
        this.compilerVersion = compilerVersion;
    }

    public Integer getSourceSizeBytes() {
        return sourceSizeBytes;
    }

    public void setSourceSizeBytes(Integer sourceSizeBytes) {
        this.sourceSizeBytes = sourceSizeBytes;
    }

    public DeploymentDecision getDeploymentDecision() {
        return deploymentDecision;
    }

    public void setDeploymentDecision(DeploymentDecision deploymentDecision) {
        this.deploymentDecision = deploymentDecision;
    }

    public Double getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(Double riskScore) {
        this.riskScore = riskScore;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getSubmittedByNode() {
        return submittedByNode;
    }

    public void setSubmittedByNode(String submittedByNode) {
        this.submittedByNode = submittedByNode;
    }

    public Integer getCriticalCount() {
        return criticalCount;
    }

    public void setCriticalCount(Integer criticalCount) {
        this.criticalCount = criticalCount;
    }

    public Integer getHighCount() {
        return highCount;
    }

    public void setHighCount(Integer highCount) {
        this.highCount = highCount;
    }

    public Integer getMediumCount() {
        return mediumCount;
    }

    public void setMediumCount(Integer mediumCount) {
        this.mediumCount = mediumCount;
    }

    public Integer getLowCount() {
        return lowCount;
    }

    public void setLowCount(Integer lowCount) {
        this.lowCount = lowCount;
    }

    public Integer getInfoCount() {
        return infoCount;
    }

    public void setInfoCount(Integer infoCount) {
        this.infoCount = infoCount;
    }

    public String getAgenticTrace() {
        return agenticTrace;
    }

    public void setAgenticTrace(String agenticTrace) {
        this.agenticTrace = agenticTrace;
    }

    public Long getLinkedThreatId() {
        return linkedThreatId;
    }

    public void setLinkedThreatId(Long linkedThreatId) {
        this.linkedThreatId = linkedThreatId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public List<AuditFinding> getFindings() {
        return findings;
    }

    public void setFindings(List<AuditFinding> findings) {
        this.findings = findings;
    }
}
