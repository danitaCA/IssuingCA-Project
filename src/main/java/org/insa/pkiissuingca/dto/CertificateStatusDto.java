package org.insa.pkiissuingca.dto;

import java.io.Serializable;
import java.time.Instant;

public class CertificateStatusDto implements Serializable {
    private static final long serialVersionUID = 1L;

    private String serialNumber;
    private String status;
    private String revocationReason;
    private Instant revocationDate;
    private Instant notBefore;
    private Instant notAfter;
    private String issuerDN;
    private String subjectDN;

    public CertificateStatusDto() {}

    public CertificateStatusDto(String serialNumber, String status, String revocationReason,
                                Instant revocationDate, Instant notBefore, Instant notAfter,
                                String issuerDN, String subjectDN) {
        this.serialNumber = serialNumber;
        this.status = status;
        this.revocationReason = revocationReason;
        this.revocationDate = revocationDate;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.issuerDN = issuerDN;
        this.subjectDN = subjectDN;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    public Instant getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(Instant revocationDate) {
        this.revocationDate = revocationDate;
    }

    public Instant getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Instant notBefore) {
        this.notBefore = notBefore;
    }

    public Instant getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Instant notAfter) {
        this.notAfter = notAfter;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }
}
