package com.threatledger.backend.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AuditReportTest {

    @Test
    void shouldCreateAuditReportWithDefaultTimestamp() {
        AuditReport report = new AuditReport();
        report.setTitle("Security Review");
        report.setSummary("Findings summary");

        assertNotNull(report.getCreatedAt());
        assertEquals("Security Review", report.getTitle());
        assertEquals("Findings summary", report.getSummary());
    }
}
