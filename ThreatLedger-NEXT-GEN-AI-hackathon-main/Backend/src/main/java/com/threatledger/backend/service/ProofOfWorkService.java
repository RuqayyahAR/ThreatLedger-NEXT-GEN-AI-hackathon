package com.threatledger.backend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * "Anti-Spam Cryptographic Check" from the doc: a client must find a nonce such that
 * SHA-256(indicatorValue + nonce) starts with `difficulty` leading zero hex characters,
 * before the backend accepts the submission. This mirrors classic PoW (Bitcoin-style)
 * but with a tiny difficulty so it doesn't slow down the demo.
 */
@Service
public class ProofOfWorkService {

    // 4 leading hex zeros ~ takes a laptop a few hundred ms to a couple seconds to find.
    // Raise this if submissions are being accepted too easily; lower it if the client-side
    // puzzle-solving takes too long during your demo.
    @Value("${threatledger.pow.difficulty:4}")
    private int difficulty;

    public boolean isValid(String indicatorValue, Integer nonce) {
        if (nonce == null) {
            return false;
        }
        String hash = sha256Hex(indicatorValue + nonce);
        String requiredPrefix = "0".repeat(difficulty);
        return hash.startsWith(requiredPrefix);
    }

    public int getDifficulty() {
        return difficulty;
    }

    private String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed to exist on every JVM, this branch is effectively unreachable
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
