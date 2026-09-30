package org.insa.pkiissuingca.dto;

import lombok.Data;

@Data
public class SubCaCsrResponse {
    private String serialNumber;
    private String subjectDN;
    private String csrPem;
    private String publicKeyPEM;
    private String keyAlgorithm;
    private int keySize;
}
