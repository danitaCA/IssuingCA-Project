package org.insa.pkiissuingca.dto;

import lombok.Data;

@Data
public class EndEntityEnrollRequest {
    private String username;
    private String email;
    private String commonName;
    private String organization;
    private String country;
    private String orgUnit;
    private String state;
    private String locality;
    private String profileName;
    private String caSerialNumber;
    private String keyGenerationMode; // ADVISED_GENERATED or USER_GENERATED
    private String keyType; // RSA, EC
    private Integer keySize; // 4096, 2048, 3072, 256, 384, 521
    private String csrPem;
    private String adminPassword; // Admin password to encrypt PKCS#12 bundle
}
