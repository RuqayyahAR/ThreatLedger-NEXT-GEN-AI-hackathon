package com.threatledger.backend.dto;

import com.threatledger.backend.entity.AuditFinding;
import com.threatledger.backend.entity.AuditReport;

import java.time.Instant;
import java.util.List;

/**
 * Audit report sent back to the dashboard - includes the full findings list
 * so the frontend can render a scrollable vulnerability list with severity
 * badges and per-finding AI confidence bars.
 */
public class AuditResponse {

    private Long reportId;
    private String contractName;
    private String sourceHash;
    private String compilerVersion;
    private Integer sourceSizeBytes;
    private String deploymentDecision;
    private Double riskScore;
    private String summary;
    private String submittedByNode;
    private Integer criticalCount, highCount, mediumCount, lowCount, infoCount;
    private String agenticTrace;
    private Long linkedThreatId;
    private Instant createdAt;
    private List<AuditFinding> findings;

    public static AuditResponse fromEntity(AuditReport r) {
        AuditResponse a = new AuditResponse();
        a.reportId = r.getReportId();
        a.contractName = r.getContractName();
        a.sourceHash = r.getSourceHash();
        a.compilerVersion = r.getCompilerVersion();
        a.sourceSizeBytes = r.getSourceSizeBytes();
        a.deploymentDecision = r.getDeploymentDecision().name();
        a.riskScore = r.getRiskScore();
        a.summary = r.getSummary();
        a.submittedByNode = r.getSubmittedByNode();
        a.criticalCount = r.getCriticalCount();
        a.highCount = r.getHighCount();
        a.mediumCount = r.getMediumCount();
        a.lowCount = r.getLowCount();
        a.infoCount = r.getInfoCount();
        a.agenticTrace = r.getAgenticTrace();
        a.linkedThreatId = r.getLinkedThreatId();
        a.createdAt = r.getCreatedAt();
        a.findings = r.getFindings();
        return a;
    }

    public Long getReportId() { return reportId; }
    public String getContractName() { return contractName; }
    public String getSourceHash() { return sourceHash; }
    public String getCompilerVersion() { return compilerVersion; }
    public Integer getSourceSizeBytes() { return sourceSizeBytes; }
    public String getDeploymentDecision() { return deploymentDecision; }
    public Double getRiskScore() { return riskScore; }
    public String getSummary() { return summary; }
    public String getSubmittedByNode() { return submittedByNode; }
    public Integer getCriticalCount() { return criticalCount; }
    public Integer getHighCount() { return highCount; }
    public Integer getMediumCount() { return mediumCount; }
    public Integer getLowCount() { return lowCount; }
    public Integer getInfoCount() { return infoCount; }
    public String getAgenticTrace() { return agenticTrace; }
    public Long getLinkedThreatId() { return linkedThreatId; }
    public Instant getCreatedAt() { return createdAt; }
    public List<AuditFinding> getFindings() { return findings; }
}
