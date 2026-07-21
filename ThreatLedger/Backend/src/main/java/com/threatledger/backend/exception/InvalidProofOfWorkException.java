package com.threatledger.backend.exception;

public class InvalidProofOfWorkException extends RuntimeException {
    public InvalidProofOfWorkException(String message) {
        super(message);
    }
}
