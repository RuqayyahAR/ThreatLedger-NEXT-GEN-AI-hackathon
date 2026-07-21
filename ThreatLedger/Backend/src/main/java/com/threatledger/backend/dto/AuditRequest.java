package com.threatledger.backend.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Payload for the AI agentic Solidity auditor endpoint. The auditor's
 * reasoning loop is fully driven by what's in the submitted source - the
 * only extra fields are optional metadata that improves the verdict's
 * explanation.
 */
public class AuditRequest {

    @NotBlank(message = "soliditySource is required")
    private String soliditySource;

    private String contractName;
    private String compilerVersion;

    @NotBlank(message = "submittedByNode is required (use 'AI-AUDITOR' if anonymous)")
    private String submittedByNode;

    private Boolean escalateToThreatFeed = true;

    public String getSoliditySource() { return soliditySource; }
    public void setSoliditySource(String s) { this.soliditySource = s; }
    public String getContractName() { return contractName; }
    public void setContractName(String c) { this.contractName = c; }
    public String getCompilerVersion() { return compilerVersion; }
    public void setCompilerVersion(String c) { this.compilerVersion = c; }
    public String getSubmittedByNode() { return submittedByNode; }
    public void setSubmittedByNode(String n) { this.submittedByNode = n; }
    public Boolean getEscalateToThreatFeed() { return escalateToThreatFeed; }
    public void setEscalateToThreatFeed(Boolean e) { this.escalateToThreatFeed = e; }
}
