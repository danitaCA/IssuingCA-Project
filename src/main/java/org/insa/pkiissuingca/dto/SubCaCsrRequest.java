package org.insa.pkiissuingca.dto;

import lombok.Data;

@Data
public class SubCaCsrRequest {
    private String subjectDN;
    private String keyType; // RSA, EC, Ed25519
    private int keySizeOrCurve; // 4096 (default), 2048, 3072, 256, 384, 521
    private String signatureAlgorithm; // SHA512withRSA, SHA384withRSA, SHA256withRSA, SHA512withECDSA, etc.
}
