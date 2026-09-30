package org.insa.pkiissuingca.dto;

import lombok.Data;
import org.insa.pkiissuingca.model.CertificateEntity;

@Data
public class EndEntityEnrollResponse {
    private CertificateEntity certificate;
    private String pkcs12Base64;
    private String certificatePem;
    private String chainPem;
    private String message;
}
