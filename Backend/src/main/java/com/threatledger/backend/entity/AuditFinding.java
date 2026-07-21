package com.threatledger.backend.entity;

import jakarta.persistence.*;

/**
 * A single vulnerability discovered by the AI auditor against a Solidity
 * codebase. Many findings belong to one {@link AuditReport}.
 *
 * The detectorId / lineStart / lineEnd / snippet fields let the frontend
 * render a precise, navigable report - similar to Slither/Mythril output.
 */
@Entity
@Table(name = "audit_findings")
public class AuditFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "finding_id")
    private Long findingId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "report_id", nullable = false)
    private AuditReport report;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    private AuditSeverity severity;

    @Column(name = "detector_id", nullable = false)
    private String detectorId; // e.g. "REENTRANCY", "INTEGER_OVERFLOW", "GAS_INEFFICIENT_STORAGE"

    @Column(name = "detector_label", nullable = false)
    private String detectorLabel; // human-readable, e.g. "Reentrancy vulnerability"

    @Column(name = "description", length = 2000)
    private String description;

    @Column(name = "location_hint")
    private String locationHint; // e.g. "VulnerableStorage.withsecureWithdraw()"

    @Column(name = "line_start")
    private Integer lineStart;

    @Column(name = "line_end")
    private Integer lineEnd;

    @Column(name = "snippet", length = 1000)
    private String snippet;

    @Column(name = "recommendation", length = 2000)
    private String recommendation;

    @Column(name = "ai_confidence")
    private Double aiConfidence; // 0.0 - 1.0 confidence of the AI heuristic

    public AuditFinding() {
    }

    public Long getFindingId() {
        return findingId;
    }

    public void setFindingId(Long findingId) {
        this.findingId = findingId;
    }

    public AuditReport getReport() {
        return report;
    }

    public void setReport(AuditReport report) {
        this.report = report;
    }

    public AuditSeverity getSeverity() {
        return severity;
    }

    public void setSeverity(AuditSeverity severity) {
        this.severity = severity;
    }

    public String getDetectorId() {
        return detectorId;
    }

    public void setDetectorId(String detectorId) {
        this.detectorId = detectorId;
    }

    public String getDetectorLabel() {
        return detectorLabel;
    }

    public void setDetectorLabel(String detectorLabel) {
        this.detectorLabel = detectorLabel;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getLocationHint() {
        return locationHint;
    }

    public void setLocationHint(String locationHint) {
        this.locationHint = locationHint;
    }

    public Integer getLineStart() {
        return lineStart;
    }

    public void setLineStart(Integer lineStart) {
        this.lineStart = lineStart;
    }

    public Integer getLineEnd() {
        return lineEnd;
    }

    public void setLineEnd(Integer lineEnd) {
        this.lineEnd = lineEnd;
    }

    public String getSnippet() {
        return snippet;
    }

    public void setSnippet(String snippet) {
        this.snippet = snippet;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public Double getAiConfidence() {
        return aiConfidence;
    }

    public void setAiConfidence(Double aiConfidence) {
        this.aiConfidence = aiConfidence;
    }
}
