package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
public class ReportEngineTest {

    @Autowired
    private ReportService reportService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private AuditService auditService;

    @Test
    @DisplayName("Should generate valid Certificate Inventory PDF with JasperReports and OpenPDF engines")
    void testGenerateCertificateInventoryPdf() {
        // Seed a sample certificate
        CertificateEntity cert = new CertificateEntity();
        cert.setSerialNumber("1234567890ABCDEF");
        cert.setSubjectDN("CN=Test Web Server,O=INSA,C=FR");
        cert.setIssuerDN("CN=INSA Sub CA,O=INSA,C=FR");
        cert.setStatus("ACTIVE");
        cert.setCertificateType("END_ENTITY");
        cert.setProfileName("EndEntity");
        cert.setPublicKeyPEM("-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----");
        cert.setNotBefore(Instant.now().minus(1, ChronoUnit.DAYS));
        cert.setNotAfter(Instant.now().plus(365, ChronoUnit.DAYS));
        cert.setPemContent("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----");
        certificateRepository.save(cert);

        // Test Jasper engine
        byte[] jasperBytes = reportService.generateCertificateInventoryPdf("auditor_user", "jasper");
        assertNotNull(jasperBytes);
        assertTrue(jasperBytes.length > 500, "Jasper PDF size should be non-trivial");
        String jasperHeader = new String(jasperBytes, 0, Math.min(jasperBytes.length, 5), StandardCharsets.US_ASCII);
        assertEquals("%PDF-", jasperHeader);

        // Test OpenPDF engine
        byte[] openPdfBytes = reportService.generateCertificateInventoryPdf("auditor_user", "openpdf");
        assertNotNull(openPdfBytes);
        assertTrue(openPdfBytes.length > 500, "OpenPDF size should be non-trivial");
        String openPdfHeader = new String(openPdfBytes, 0, Math.min(openPdfBytes.length, 5), StandardCharsets.US_ASCII);
        assertEquals("%PDF-", openPdfHeader);
    }

    @Test
    @DisplayName("Should generate valid Audit Trail PDF with JasperReports and OpenPDF engines")
    void testGenerateAuditTrailPdf() {
        auditService.log("admin", "INIT_CA", "Root CA Created", "SUCCESS", "127.0.0.1");
        auditService.log("operator", "SIGN_CSR", "CSR Signed for Bob", "SUCCESS", "192.168.1.50");

        // Test Jasper engine
        byte[] jasperBytes = reportService.generateAuditTrailPdf("auditor_user", "jasper");
        assertNotNull(jasperBytes);
        assertTrue(jasperBytes.length > 500);
        String jasperHeader = new String(jasperBytes, 0, Math.min(jasperBytes.length, 5), StandardCharsets.US_ASCII);
        assertEquals("%PDF-", jasperHeader);

        // Test OpenPDF engine
        byte[] openPdfBytes = reportService.generateAuditTrailPdf("auditor_user", "openpdf");
        assertNotNull(openPdfBytes);
        assertTrue(openPdfBytes.length > 500);
        String openPdfHeader = new String(openPdfBytes, 0, Math.min(openPdfBytes.length, 5), StandardCharsets.US_ASCII);
        assertEquals("%PDF-", openPdfHeader);
    }

    @Test
    @DisplayName("Should generate valid Executive Compliance Report PDF with %PDF header")
    void testGenerateComplianceReportPdf() {
        byte[] pdfBytes = reportService.generateComplianceReportPdf("security_officer");
        assertNotNull(pdfBytes);
        assertTrue(pdfBytes.length > 500);

        String header = new String(pdfBytes, 0, Math.min(pdfBytes.length, 5), StandardCharsets.US_ASCII);
        assertEquals("%PDF-", header);
    }

    @Test
    @DisplayName("Should export Certificate Inventory as valid CSV with correct headers")
    void testGenerateCertificateInventoryCsv() {
        String csv = reportService.generateCertificateInventoryCsv();
        assertNotNull(csv);
        assertTrue(csv.contains("SerialNumber"));
        assertTrue(csv.contains("SubjectDN"));
        assertTrue(csv.contains("Status"));
    }
}
