package com.threatledger.backend.entity;

/**
 * Matches the "indicatorType" field in the data contract: IP, DOMAIN, or HASH.
 */
public enum IndicatorType {
    IP,
    DOMAIN,
    HASH
}
