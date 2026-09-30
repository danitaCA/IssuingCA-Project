package org.insa.pkiissuingca.dto;

import lombok.Data;

@Data
public class ImportSignedCaCertRequest {
    private String caSerialNumber;
    private String signedCertPem;
}
