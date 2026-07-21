package com.threatledger.backend.controller;

import com.threatledger.backend.dto.CreateProfileRequest;
import com.threatledger.backend.dto.IssueCredentialRequest;
import com.threatledger.backend.dto.GenerateProofRequest;
import com.threatledger.backend.dto.ReputationResponse;
import com.threatledger.backend.dto.VerifyProofRequest;
import com.threatledger.backend.entity.ReputationProfile;
import com.threatledger.backend.entity.ZkCredential;
import com.threatledger.backend.entity.ZkProofRecord;
import com.threatledger.backend.service.ZkReputationService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Decentralized ZK reputation protocol endpoints.
 *
 *   POST /api/reputation/profiles                                -> create profile
 *   GET  /api/reputation/profiles                                -> list profiles
 *   GET  /api/reputation/profiles/{profileId}                    -> fetch profile
 *   POST /api/reputation/profiles/{profileId}/credentials        -> issue credential
 *   POST /api/reputation/profiles/{profileId}/proofs             -> generate ZK proof
 *   POST /api/reputation/proofs/verify                           -> verify ZK proof
 *   GET  /api/reputation/proofs                                  -> list proofs
 *   POST /api/reputation/profiles/{profileId}/membership         -> build membership proof
 *   POST /api/reputation/membership/verify                       -> verify membership proof
 *
 * Every proof record is written to `zk_proof_records` for transparency, but
 * the service never reads back PII because none is ever stored.
 */
@RestController
@RequestMapping("/api/reputation")
public class ReputationController {

    private final ZkReputationService reputationService;

    public ReputationController(ZkReputationService reputationService) {
        this.reputationService = reputationService;
    }

    @PostMapping("/profiles")
    public ResponseEntity<ReputationResponse> createProfile(@Valid @RequestBody CreateProfileRequest req) {
        ReputationProfile p = reputationService.createProfile(
            req.getSecretIdentityMaterial(), req.getNodeId());
        return ResponseEntity.status(HttpStatus.CREATED).body(ReputationResponse.fromEntity(p));
    }

    @GetMapping("/profiles")
    public ResponseEntity<List<ReputationResponse>> listProfiles() {
        return ResponseEntity.ok(reputationService.listProfiles().stream()
            .map(ReputationResponse::fromEntity).toList());
    }

    @GetMapping("/profiles/{profileId}")
    public ResponseEntity<ReputationResponse> getProfile(@PathVariable Long profileId) {
        return ResponseEntity.ok(ReputationResponse.fromEntity(reputationService.getProfile(profileId)));
    }

    @PostMapping("/profiles/{profileId}/credentials")
    public ResponseEntity<Map<String, Object>> issueCredential(
        @PathVariable Long profileId, @Valid @RequestBody IssueCredentialRequest req) {
        ZkCredential cred = reputationService.issueCredential(
            profileId, req.getClaimType(), req.getIssuerId(), req.getSecretForCommitment());
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
            "credentialId", cred.getCredentialId(),
            "claimType", cred.getClaimType().name(),
            "issuerId", cred.getIssuerId(),
            "commitmentLeaf", cred.getCommitmentLeaf().substring(0, 24) + "...",
            "saltLength", cred.getSalt().length(),
            "issuedAt", cred.getIssuedAt()
        ));
    }

    @PostMapping("/profiles/{profileId}/proofs")
    public ResponseEntity<ZkProofRecord> generateProof(
        @PathVariable Long profileId, @Valid @RequestBody GenerateProofRequest req) {
        if (!profileId.equals(req.getProfileId())) {
            throw new IllegalArgumentException("profileId in path and body must match");
        }
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(reputationService.generateIdentityProof(profileId, req.getSecretHex(),
                req.getTranscript(), req.getVerifierId()));
    }

    @PostMapping("/proofs/verify")
    public ResponseEntity<ZkProofRecord> verifyProof(@Valid @RequestBody VerifyProofRequest req) {
        return ResponseEntity.ok(reputationService.verifyIdentityProof(req.getProofId(), req.getTranscript()));
    }

    @GetMapping("/proofs")
    public ResponseEntity<List<ZkProofRecord>> listProofs() {
        return ResponseEntity.ok(reputationService.listProofs());
    }

    @PostMapping("/profiles/{profileId}/membership")
    public ResponseEntity<ZkReputationService.MerkleProof> buildMembership(
        @PathVariable Long profileId,
        @RequestBody Map<String, String> body) {
        String claimStr = body.get("claimType");
        if (claimStr == null) throw new IllegalArgumentException("claimType required");
        return ResponseEntity.status(HttpStatus.CREATED)
            .body(reputationService.buildMembershipProof(
                profileId,
                com.threatledger.backend.entity.ClaimType.valueOf(claimStr.toUpperCase())));
    }

    @PostMapping("/membership/verify")
    public ResponseEntity<Map<String, Object>> verifyMembership(
        @RequestBody ZkReputationService.MerkleProof proof) {
        boolean ok = reputationService.verifyMembershipProof(proof);
        return ResponseEntity.ok(Map.of("verified", ok, "issuerId", proof.issuerId(),
            "claimType", proof.claimType().name()));
    }
}
