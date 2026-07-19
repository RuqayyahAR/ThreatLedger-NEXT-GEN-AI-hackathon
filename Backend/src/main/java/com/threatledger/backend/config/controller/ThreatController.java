package com.threatledger.backend.controller;

import com.threatledger.backend.dto.ThreatResponse;
import com.threatledger.backend.dto.ThreatSubmissionRequest;
import com.threatledger.backend.dto.VoteRequest;
import com.threatledger.backend.entity.ConsensusStatus;
import com.threatledger.backend.service.ThreatService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/threats")
public class ThreatController {

    private final ThreatService threatService;

    public ThreatController(ThreatService threatService) {
        this.threatService = threatService;
    }

    // Frontend -> POST a new threat report. Requires a valid proof-of-work nonce.
    @PostMapping
    public ResponseEntity<ThreatResponse> submitThreat(@Valid @RequestBody ThreatSubmissionRequest request) {
        ThreatResponse response = threatService.submitThreat(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // Frontend dashboard AND Python agent both call this.
    // Python agent should call GET /api/threats?status=VERIFIED to only pull items to block.
    @GetMapping
    public ResponseEntity<List<ThreatResponse>> getThreats(
            @RequestParam(required = false) ConsensusStatus status) {
        return ResponseEntity.ok(threatService.getAllThreats(status));
    }

    @GetMapping("/{indicatorId}")
    public ResponseEntity<ThreatResponse> getThreat(@PathVariable Long indicatorId) {
        return ResponseEntity.ok(threatService.getThreatById(indicatorId));
    }

    // Peer nodes cast a vote on a submitted threat. Drives the consensus engine.
    @PostMapping("/{indicatorId}/vote")
    public ResponseEntity<ThreatResponse> castVote(
            @PathVariable Long indicatorId,
            @Valid @RequestBody VoteRequest request) {
        return ResponseEntity.ok(threatService.castVote(indicatorId, request));
    }
}
