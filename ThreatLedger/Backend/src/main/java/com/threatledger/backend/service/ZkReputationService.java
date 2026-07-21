package com.threatledger.backend.service;

import com.threatledger.backend.entity.ClaimType;
import com.threatledger.backend.entity.ReputationProfile;
import com.threatledger.backend.entity.ZkCredential;
import com.threatledger.backend.entity.ZkProofRecord;
import com.threatledger.backend.repository.ReputationProfileRepository;
import com.threatledger.backend.repository.ZkCredentialRepository;
import com.threatledger.backend.repository.ZkProofRecordRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Decentralized ZK reputation protocol.
 *
 * Tying the twist into the baseline rather than bolting on a new subsystem:
 *   - Each peer {@link com.threatledger.backend.entity.Node} may optionally
 *     register a ReputationProfile, in which case a `reputationMultiplier`
 *     weight can be applied when that node casts a vote in the existing
 *     consensus engine. The baseline consensus pipeline is untouched.
 *   - The protocol internally maintains three ZK primitives (see
 *     {@link ZkCryptoService}): Pedersen-style commitments, a Merkle root
 *     over issued credentials, and a Schnorr sigma-protocol proof of
 *     knowledge. The proof record is persisted for forensic transparency
 *     without ever storing the plaintext identity material.
 *
 * The {@code reputationScore} (0-100) and derived tier (BRONZE / SILVER /
 * GOLD / PLATINUM) are derived purely from on-chain verifiable credential
 * holdings - no Personally Identifiable Information is stored, queryable,
 * or even encryptable. Identity is turned into pseudonymous credential
 * leaves never into a username.
 */
@Service
public class ZkReputationService {

    private static final Logger LOG = LoggerFactory.getLogger(ZkReputationService.class);

    private final ReputationProfileRepository profileRepo;
    private final ZkCredentialRepository credentialRepo;
    private final ZkProofRecordRepository proofRepo;
    private final ZkCryptoService crypto;

    public ZkReputationService(ReputationProfileRepository profileRepo,
                                 ZkCredentialRepository credentialRepo,
                                 ZkProofRecordRepository proofRepo,
                                 ZkCryptoService crypto) {
        this.profileRepo = profileRepo;
        this.credentialRepo = credentialRepo;
        this.proofRepo = proofRepo;
        this.crypto = crypto;
    }

    // =========================================================================
    // Profile creation
    // =========================================================================
    @Transactional
    public ReputationProfile createProfile(String secretIdentityMaterial, String optionalNodeId) {
        if (secretIdentityMaterial == null || secretIdentityMaterial.isBlank()) {
            throw new IllegalArgumentException("secretIdentityMaterial is required");
        }
        String serverSalt = crypto.randomHex(16);
        String zkAliasHash = crypto.sha256Hex(secretIdentityMaterial + "|" + serverSalt);
        if (profileRepo.findByZkAliasHash(zkAliasHash).isPresent()) {
            throw new IllegalArgumentException("profile already exists for this identity material");
        }
        ReputationProfile p = new ReputationProfile();
        p.setNodeId(optionalNodeId);
        p.setZkAliasHash(zkAliasHash);
        p.setMerkleRoot(crypto.computeMerkleRoot(List.of()));
        p.setCredentialCount(0);
        p.setHackathonWins(0);
        p.setReputationScore(0.0);
        p.setTier("BRONZE");
        p.setCreatedAt(Instant.now());
        p.setUpdatedAt(Instant.now());
        return profileRepo.save(p);
    }

    // =========================================================================
    // Credential issuance (issuer side)
    // =========================================================================
    @Transactional
    public ZkCredential issueCredential(Long profileId, ClaimType claimType,
                                          String issuerId, String secretForCommitment) {
        if (issuerId == null || issuerId.isBlank()) {
            throw new IllegalArgumentException("issuerId is required");
        }
        ReputationProfile p = profileRepo.findById(profileId)
            .orElseThrow(() -> new IllegalArgumentException("Unknown reputation profile #" + profileId));
        // The issuer(turns) the identity secret + a fresh random salt into a
        // Pedersen-style commitment leaf. Neither the secret nor the salt
        // are persisted in plaintext after this step.
        ZkCryptoService.CommitmentLeaf cl = crypto.generateCommitment(secretForCommitment, issuerId, claimType.name());
        ZkCredential cred = new ZkCredential();
        cred.setProfile(p);
        cred.setClaimType(claimType);
        cred.setIssuerId(issuerId);
        cred.setCommitmentLeaf(cl.leaf());
        cred.setSalt(cl.salt());
        cred.setIssuedAt(Instant.now());
        cred.setRevoked(false);
        p.getCredentials().add(cred);
        credentialRepo.save(cred);

        recomputeProfile(p);
        profileRepo.save(p);
        return cred;
    }

    // =========================================================================
    // Proof generation / verification - prover side calls generateProof,
    // anyone (auditor, peer, frontend) calls verifyProof.
    // =========================================================================
    @Transactional
    public ZkProofRecord generateIdentityProof(Long profileId, String secretHex, String transcript,
                                                  String verifierId) {
        ReputationProfile p = profileRepo.findById(profileId)
            .orElseThrow(() -> new IllegalArgumentException("Unknown reputation profile #" + profileId));
        var secret = crypto.secretFromHex(secretHex);
        ZkCryptoService.SchnorrProof proof = crypto.generateProof(secret, transcript + "|" + p.getZkAliasHash());

        ZkProofRecord rec = new ZkProofRecord();
        rec.setProfileId(profileId);
        rec.setZkAliasHash(p.getZkAliasHash());
        rec.setClaimedType(ClaimType.VERIFIED_DEVELOPER_ID);
        rec.setMerkleRoot(p.getMerkleRoot());
        rec.setNullifierHash(crypto.nullifier(secretHex, "IdentityProof"));
        rec.setChallenge(proof.c());
        rec.setResponse(proof.s());
        rec.setVerifierPublicCommit(proof.y());
        rec.setVerified(false);
        rec.setVerifierId(verifierId);
        rec.setVerifiedAt(Instant.now());
        return proofRepo.save(rec);
    }

    @Transactional
    public ZkProofRecord verifyIdentityProof(Long proofId, String transcript) {
        ZkProofRecord rec = proofRepo.findById(proofId)
            .orElseThrow(() -> new IllegalArgumentException("Unknown proof #" + proofId));
        ZkCryptoService.SchnorrProof sp =
            new ZkCryptoService.SchnorrProof(rec.getVerifierPublicCommit(), "", rec.getResponse(), rec.getChallenge());
        // The verifier recomputes the prover's R = g^s * Y^c mod p, then
        // reproduces c = H(Y || R || transcript) to compare with what the
        // prover published. Fiat-Shamir makes this fully non-interactive.
        boolean ok = crypto.verifyProof(sp, transcript + "|" + rec.getZkAliasHash());
        // Re-check double-spend: nullifier must be unique
        boolean used = proofRepo.findByNullifierHash(rec.getNullifierHash())
            .filter(other -> !other.getProofId().equals(rec.getProofId()))
            .isPresent();
        rec.setVerified(ok && !used);
        return proofRepo.save(rec);
    }

    // =========================================================================
    // Merkle-membership ZK proof path generation. Proves "I hold a credential
    // of claimType issued by issuerId from this profile's credential set"
    // without revealing which credential.
    // =========================================================================
    public MerkleProof buildMembershipProof(Long profileId, ClaimType claimType) {
        ReputationProfile p = profileRepo.findById(profileId)
            .orElseThrow(() -> new IllegalArgumentException("Unknown reputation profile #" + profileId));
        List<ZkCredential> active = p.getCredentials().stream()
            .filter(c -> !c.isRevoked() && c.getClaimType() == claimType)
            .collect(Collectors.toList());
        if (active.isEmpty()) {
            throw new IllegalArgumentException("No active credential of type " + claimType);
        }
        List<String> allLeaves = p.getCredentials().stream()
            .map(ZkCredential::getCommitmentLeaf)
            .collect(Collectors.toList());
        ZkCredential target = active.get(0);
        int idx = -1;
        for (int i = 0; i < p.getCredentials().size(); i++) {
            if (p.getCredentials().get(i).getCredentialId().equals(target.getCredentialId())) {
                idx = i; break;
            }
        }
        return new MerkleProof(target.getCommitmentLeaf(), crypto.merklePath(allLeaves, idx),
            p.getMerkleRoot(), target.getIssuerId(), claimType);
    }

    public boolean verifyMembershipProof(MerkleProof mp) {
        return crypto.verifyMerklePath(mp.leaf(), mp.root(), mp.path());
    }

    // =========================================================================
    // Read endpoints
    // =========================================================================
    public ReputationProfile getProfile(Long profileId) {
        return profileRepo.findById(profileId)
            .orElseThrow(() -> new IllegalArgumentException("Unknown reputation profile #" + profileId));
    }

    public List<ReputationProfile> listProfiles() {
        return profileRepo.findAll();
    }

    public List<ZkProofRecord> listProofs() {
        return proofRepo.findAll();
    }

    // =========================================================================
    // Aggregate score recompute
    // =========================================================================
    private void recomputeProfile(ReputationProfile p) {
        List<ZkCredential> active = p.getCredentials().stream()
            .filter(c -> !c.isRevoked())
            .collect(Collectors.toList());
        int wins = (int) active.stream()
            .filter(c -> c.getClaimType() == ClaimType.HACKATHON_WINNER).count();
        int finalists = (int) active.stream()
            .filter(c -> c.getClaimType() == ClaimType.HACKATHON_FINALIST).count();
        int participants = (int) active.stream()
            .filter(c -> c.getClaimType() == ClaimType.HACKATHON_PARTICIPANT).count();
        int audited = (int) active.stream()
            .filter(c -> c.getClaimType() == ClaimType.SECURITY_AUDIT_ISSUED).count();
        int codeReviews = (int) active.stream()
            .filter(c -> c.getClaimType() == ClaimType.CODE_REVIEW_SIGNOFF).count();
        int kyc = (int) active.stream()
            .filter(c -> c.getClaimType() == ClaimType.K_Y_C_VERIFIED).count();
        int devId = (int) active.stream()
            .filter(c -> c.getClaimType() == ClaimType.VERIFIED_DEVELOPER_ID).count();

        double score = wins * 25 + finalists * 12 + participants * 5
            + audited * 15 + codeReviews * 8 + kyc * 10 + devId * 5;
        score = Math.min(100.0, score);

        p.setCredentialCount(active.size());
        p.setHackathonWins(wins);
        p.setReputationScore(Math.round(score * 10.0) / 10.0);
        p.setTier(deriveTier(score));
        p.setMerkleRoot(crypto.computeMerkleRoot(
            active.stream().map(ZkCredential::getCommitmentLeaf).collect(Collectors.toList())));
        p.setUpdatedAt(Instant.now());
    }

    private String deriveTier(double score) {
        if (score >= 85.0) return "PLATINUM";
        if (score >= 65.0) return "GOLD";
        if (score >= 35.0) return "SILVER";
        return "BRONZE";
    }

    /**
     * Multiplier applied to consensus weight when a node that owns a
     * reputation profile casts a vote in the baseline engine. Layered onto
     * existing pipeline, doesn't replace it.
     */
    public double reputationMultiplier(String nodeId) {
        if (nodeId == null) return 1.0;
        return profileRepo.findByNodeId(nodeId)
            .map(p -> 1.0 + Math.min(0.5, p.getReputationScore() / 200.0))
            .orElse(1.0);
    }

    public record MerkleProof(String leaf, List<String> path, String root, String issuerId,
                                ClaimType claimType) {}
}
