package org.insa.pkiissuingca.service;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import net.sf.jasperreports.engine.*;
import net.sf.jasperreports.engine.data.JRBeanCollectionDataSource;
import org.insa.pkiissuingca.model.AuditLogEntity;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.repository.AuditLogRepository;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class ReportService {

    private static final Logger logger = LoggerFactory.getLogger(ReportService.class);
    private static final DateTimeFormatter DATE_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private AuditService auditService;

    // Cache for compiled Jasper reports
    private JasperReport compiledCertReport;
    private JasperReport compiledAuditReport;

    /**
     * Generates a Certificate Inventory PDF report using either JasperReports or OpenPDF engine.
     */
    @Transactional(readOnly = true)
    public byte[] generateCertificateInventoryPdf(String requestedBy, String engine) {
        if ("openpdf".equalsIgnoreCase(engine)) {
            return generateCertificateInventoryOpenPdf(requestedBy);
        }
        return generateCertificateInventoryJasperPdf(requestedBy);
    }

    /**
     * Default overload using JasperReports engine.
     */
    @Transactional(readOnly = true)
    public byte[] generateCertificateInventoryPdf(String requestedBy) {
        return generateCertificateInventoryPdf(requestedBy, "jasper");
    }

    /**
     * Generates an Audit Trail PDF report using either JasperReports or OpenPDF engine.
     */
    @Transactional(readOnly = true)
    public byte[] generateAuditTrailPdf(String requestedBy, String engine) {
        if ("openpdf".equalsIgnoreCase(engine)) {
            return generateAuditTrailOpenPdf(requestedBy);
        }
        return generateAuditTrailJasperPdf(requestedBy);
    }

    /**
     * Default overload using JasperReports engine.
     */
    @Transactional(readOnly = true)
    public byte[] generateAuditTrailPdf(String requestedBy) {
        return generateAuditTrailPdf(requestedBy, "jasper");
    }

    /**
     * Generates Certificate Inventory PDF using JasperReports engine.
     */
    @Transactional(readOnly = true)
    public byte[] generateCertificateInventoryJasperPdf(String requestedBy) {
        try {
            List<CertificateEntity> certs = certificateRepository.findAll(Sort.by(Sort.Direction.DESC, "id"));

            List<Map<String, Object>> dataList = new ArrayList<>();
            for (CertificateEntity c : certs) {
                Map<String, Object> map = new HashMap<>();
                map.put("id", c.getId());
                map.put("serialNumber", abbreviate(c.getSerialNumber(), 18));
                map.put("subjectDN", abbreviate(c.getSubjectDN(), 32));
                map.put("issuerDN", abbreviate(c.getIssuerDN(), 32));
                map.put("status", c.getStatus());
                map.put("certificateType", c.getCertificateType() != null ? c.getCertificateType() : "END_ENTITY");
                map.put("profileName", c.getProfileName() != null ? c.getProfileName() : "Standard");
                map.put("notBefore", c.getNotBefore() != null ? DATE_FMT.format(c.getNotBefore()) : "N/A");
                map.put("notAfter", c.getNotAfter() != null ? DATE_FMT.format(c.getNotAfter()) : "N/A");
                dataList.add(map);
            }

            if (dataList.isEmpty()) {
                Map<String, Object> emptyMap = new HashMap<>();
                emptyMap.put("serialNumber", "N/A");
                emptyMap.put("subjectDN", "No certificates issued yet");
                emptyMap.put("issuerDN", "N/A");
                emptyMap.put("status", "NONE");
                dataList.add(emptyMap);
            }

            long activeCount = certs.stream().filter(c -> "ISSUED".equalsIgnoreCase(c.getStatus()) || "ACTIVE".equalsIgnoreCase(c.getStatus())).count();
            long revokedCount = certs.stream().filter(c -> "REVOKED".equalsIgnoreCase(c.getStatus())).count();

            Map<String, Object> parameters = new HashMap<>();
            parameters.put("ReportTitle", "PKI Certificate Authority - Certificate Inventory");
            parameters.put("GeneratedBy", requestedBy != null ? requestedBy : "SYSTEM");
            parameters.put("GeneratedDate", DATE_FMT.format(Instant.now()));
            parameters.put("TotalCount", (long) certs.size());
            parameters.put("ActiveCount", activeCount);
            parameters.put("RevokedCount", revokedCount);

            JasperReport report = getOrCompileCertReport();
            JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(dataList);
            JasperPrint print = JasperFillManager.fillReport(report, parameters, dataSource);

            return JasperExportManager.exportReportToPdf(print);
        } catch (Exception e) {
            logger.error("JasperReports certificate inventory generation failed, falling back to OpenPDF", e);
            return generateCertificateInventoryOpenPdf(requestedBy);
        }
    }

    /**
     * Generates Audit Trail PDF using JasperReports engine.
     */
    @Transactional(readOnly = true)
    public byte[] generateAuditTrailJasperPdf(String requestedBy) {
        try {
            List<AuditLogEntity> logs = auditLogRepository.findAll(Sort.by(Sort.Direction.DESC, "id"));
            Map<String, Object> integrity = auditService.verifyAuditChainIntegrity();

            List<Map<String, Object>> dataList = new ArrayList<>();
            for (AuditLogEntity l : logs) {
                Map<String, Object> map = new HashMap<>();
                map.put("id", l.getId());
                map.put("timestamp", l.getTimestamp() != null ? DATE_FMT.format(l.getTimestamp()) : "N/A");
                map.put("username", l.getUsername());
                map.put("action", l.getAction());
                map.put("status", l.getStatus());
                map.put("ipAddress", l.getIpAddress() != null ? l.getIpAddress() : "127.0.0.1");
                map.put("checksum", abbreviate(l.getChecksum(), 32));
                dataList.add(map);
            }

            if (dataList.isEmpty()) {
                Map<String, Object> emptyMap = new HashMap<>();
                emptyMap.put("id", 0L);
                emptyMap.put("action", "NO_LOGS");
                emptyMap.put("status", "CLEAN");
                dataList.add(emptyMap);
            }

            boolean isValid = Boolean.TRUE.equals(integrity.get("valid"));
            String chainStatus = isValid ? "VERIFIED (Hash Chain INTACT)" : "FAILED (Hash Chain Inconsistency!)";

            Map<String, Object> parameters = new HashMap<>();
            parameters.put("ReportTitle", "PKI Audit Trail & Verification Report");
            parameters.put("GeneratedBy", requestedBy != null ? requestedBy : "SYSTEM");
            parameters.put("GeneratedDate", DATE_FMT.format(Instant.now()));
            parameters.put("ChainStatus", chainStatus);
            parameters.put("TotalRecords", logs.size());

            JasperReport report = getOrCompileAuditReport();
            JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(dataList);
            JasperPrint print = JasperFillManager.fillReport(report, parameters, dataSource);

            return JasperExportManager.exportReportToPdf(print);
        } catch (Exception e) {
            logger.error("JasperReports audit trail generation failed, falling back to OpenPDF", e);
            return generateAuditTrailOpenPdf(requestedBy);
        }
    }

    private synchronized JasperReport getOrCompileCertReport() throws JRException {
        if (compiledCertReport == null) {
            try (InputStream in = new ClassPathResource("reports/certificates_report.jrxml").getInputStream()) {
                compiledCertReport = JasperCompileManager.compileReport(in);
            } catch (Exception e) {
                throw new JRException("Failed to load certificates_report.jrxml", e);
            }
        }
        return compiledCertReport;
    }

    private synchronized JasperReport getOrCompileAuditReport() throws JRException {
        if (compiledAuditReport == null) {
            try (InputStream in = new ClassPathResource("reports/audit_report.jrxml").getInputStream()) {
                compiledAuditReport = JasperCompileManager.compileReport(in);
            } catch (Exception e) {
                throw new JRException("Failed to load audit_report.jrxml", e);
            }
        }
        return compiledAuditReport;
    }

    /**
     * Generates a PDF report summarizing all certificates in the PKI inventory via OpenPDF.
     */
    @Transactional(readOnly = true)
    public byte[] generateCertificateInventoryOpenPdf(String requestedBy) {
        List<CertificateEntity> certs = certificateRepository.findAll(Sort.by(Sort.Direction.DESC, "id"));
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        Document document = new Document(PageSize.A4.rotate(), 20, 20, 30, 30);
        PdfWriter.getInstance(document, out);
        document.open();

        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, new Color(33, 37, 41));
        Font subTitleFont = FontFactory.getFont(FontFactory.HELVETICA, 10, new Color(108, 117, 125));
        Font headerFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Color.WHITE);
        Font cellFont = FontFactory.getFont(FontFactory.HELVETICA, 9, new Color(33, 37, 41));
        Font statFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 11, new Color(13, 110, 253));

        Paragraph title = new Paragraph("PKI Certificate Authority - Certificate Inventory Report", titleFont);
        title.setAlignment(Element.ALIGN_LEFT);
        document.add(title);

        Paragraph metadata = new Paragraph(String.format("Generated on: %s | Requested by: %s | Total Certificates: %d",
                DATE_FMT.format(Instant.now()), requestedBy != null ? requestedBy : "SYSTEM", certs.size()), subTitleFont);
        metadata.setSpacingAfter(15);
        document.add(metadata);

        long activeCount = certs.stream().filter(c -> "ISSUED".equalsIgnoreCase(c.getStatus()) || "ACTIVE".equalsIgnoreCase(c.getStatus())).count();
        long revokedCount = certs.stream().filter(c -> "REVOKED".equalsIgnoreCase(c.getStatus())).count();
        long suspendedCount = certs.stream().filter(c -> "SUSPENDED".equalsIgnoreCase(c.getStatus())).count();

        PdfPTable statsTable = new PdfPTable(3);
        statsTable.setWidthPercentage(100);
        statsTable.setSpacingAfter(15);

        addStatCell(statsTable, "ACTIVE / ISSUED", String.valueOf(activeCount), new Color(25, 135, 84), cellFont, statFont);
        addStatCell(statsTable, "REVOKED CERTIFICATES", String.valueOf(revokedCount), new Color(220, 53, 69), cellFont, statFont);
        addStatCell(statsTable, "SUSPENDED CERTIFICATES", String.valueOf(suspendedCount), new Color(255, 193, 7), cellFont, statFont);
        document.add(statsTable);

        PdfPTable table = new PdfPTable(7);
        table.setWidthPercentage(100);
        table.setWidths(new float[]{1.5f, 2.5f, 2.5f, 1.2f, 1.2f, 1.5f, 1.5f});

        String[] headers = {"Serial Number", "Subject DN", "Issuer DN", "Profile", "Status", "Valid From", "Valid To"};
        for (String h : headers) {
            PdfPCell cell = new PdfPCell(new Phrase(h, headerFont));
            cell.setBackgroundColor(new Color(33, 37, 41));
            cell.setPadding(6);
            cell.setHorizontalAlignment(Element.ALIGN_CENTER);
            table.addCell(cell);
        }

        boolean alt = false;
        for (CertificateEntity c : certs) {
            Color rowColor = alt ? new Color(248, 249, 250) : Color.WHITE;
            alt = !alt;

            addTableCell(table, abbreviate(c.getSerialNumber(), 16), cellFont, rowColor, Element.ALIGN_CENTER);
            addTableCell(table, abbreviate(c.getSubjectDN(), 30), cellFont, rowColor, Element.ALIGN_LEFT);
            addTableCell(table, abbreviate(c.getIssuerDN(), 30), cellFont, rowColor, Element.ALIGN_LEFT);
            addTableCell(table, c.getProfileName() != null ? c.getProfileName() : "Standard", cellFont, rowColor, Element.ALIGN_CENTER);
            addTableCell(table, c.getStatus() != null ? c.getStatus() : "UNKNOWN", cellFont, rowColor, Element.ALIGN_CENTER);
            addTableCell(table, c.getNotBefore() != null ? DATE_FMT.format(c.getNotBefore()) : "N/A", cellFont, rowColor, Element.ALIGN_CENTER);
            addTableCell(table, c.getNotAfter() != null ? DATE_FMT.format(c.getNotAfter()) : "N/A", cellFont, rowColor, Element.ALIGN_CENTER);
        }

        document.add(table);
        document.close();
        return out.toByteArray();
    }

    /**
     * Generates a PDF report for Audit Trail and Cryptographic Chain Verification via OpenPDF.
     */
    @Transactional(readOnly = true)
    public byte[] generateAuditTrailOpenPdf(String requestedBy) {
        List<AuditLogEntity> logs = auditLogRepository.findAll(Sort.by(Sort.Direction.DESC, "id"));
        Map<String, Object> integrity = auditService.verifyAuditChainIntegrity();
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        Document document = new Document(PageSize.A4.rotate(), 20, 20, 30, 30);
        PdfWriter.getInstance(document, out);
        document.open();

        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 18, new Color(33, 37, 41));
        Font subTitleFont = FontFactory.getFont(FontFactory.HELVETICA, 10, new Color(108, 117, 125));
        Font headerFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Color.WHITE);
        Font cellFont = FontFactory.getFont(FontFactory.HELVETICA, 9, new Color(33, 37, 41));

        Paragraph title = new Paragraph("PKI Audit Trail & Cryptographic Verification Report", titleFont);
        document.add(title);

        boolean isValid = Boolean.TRUE.equals(integrity.get("valid"));
        String statusLabel = isValid ? "VERIFIED (Tamper-Evident Hash Chain INTACT)" : "FAILED (Hash Chain Inconsistency Detected!)";
        Color statusColor = isValid ? new Color(25, 135, 84) : new Color(220, 53, 69);

        Paragraph chainStatus = new Paragraph(String.format("Chain Integrity: %s | Verified Records: %s",
                statusLabel, integrity.get("totalRecordsChecked")), FontFactory.getFont(FontFactory.HELVETICA_BOLD, 11, statusColor));
        chainStatus.setSpacingBefore(5);
        document.add(chainStatus);

        Paragraph metadata = new Paragraph(String.format("Generated on: %s | Requested by: %s",
                DATE_FMT.format(Instant.now()), requestedBy != null ? requestedBy : "SYSTEM"), subTitleFont);
        metadata.setSpacingAfter(15);
        document.add(metadata);

        PdfPTable table = new PdfPTable(7);
        table.setWidthPercentage(100);
        table.setWidths(new float[]{1.0f, 2.0f, 1.5f, 2.0f, 1.2f, 1.5f, 3.0f});

        String[] headers = {"ID", "Timestamp", "User", "Action", "Status", "IP Address", "Chained Checksum (SHA-256)"};
        for (String h : headers) {
            PdfPCell cell = new PdfPCell(new Phrase(h, headerFont));
            cell.setBackgroundColor(new Color(33, 37, 41));
            cell.setPadding(6);
            cell.setHorizontalAlignment(Element.ALIGN_CENTER);
            table.addCell(cell);
        }

        boolean alt = false;
        for (AuditLogEntity l : logs) {
            Color rowColor = alt ? new Color(248, 249, 250) : Color.WHITE;
            alt = !alt;

            addTableCell(table, String.valueOf(l.getId()), cellFont, rowColor, Element.ALIGN_CENTER);
            addTableCell(table, l.getTimestamp() != null ? DATE_FMT.format(l.getTimestamp()) : "N/A", cellFont, rowColor, Element.ALIGN_CENTER);
            addTableCell(table, l.getUsername(), cellFont, rowColor, Element.ALIGN_LEFT);
            addTableCell(table, l.getAction(), cellFont, rowColor, Element.ALIGN_LEFT);
            addTableCell(table, l.getStatus(), cellFont, rowColor, Element.ALIGN_CENTER);
            addTableCell(table, l.getIpAddress() != null ? l.getIpAddress() : "127.0.0.1", cellFont, rowColor, Element.ALIGN_CENTER);
            addTableCell(table, abbreviate(l.getChecksum(), 24), cellFont, rowColor, Element.ALIGN_LEFT);
        }

        document.add(table);
        document.close();
        return out.toByteArray();
    }

    /**
     * Generates an Executive Security & Compliance Report PDF.
     */
    @Transactional(readOnly = true)
    public byte[] generateComplianceReportPdf(String requestedBy) {
        List<CertificateEntity> certs = certificateRepository.findAll();
        Map<String, Object> integrity = auditService.verifyAuditChainIntegrity();
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        Document document = new Document(PageSize.A4, 30, 30, 30, 30);
        PdfWriter.getInstance(document, out);
        document.open();

        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, new Color(33, 37, 41));
        Font h2Font = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, new Color(13, 110, 253));
        Font subTitleFont = FontFactory.getFont(FontFactory.HELVETICA, 10, new Color(108, 117, 125));
        Font bodyFont = FontFactory.getFont(FontFactory.HELVETICA, 10, new Color(33, 37, 41));
        Font headerFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Color.WHITE);

        Paragraph title = new Paragraph("PKI Infrastructure Compliance & Governance Report", titleFont);
        document.add(title);

        Paragraph meta = new Paragraph("Executive Audit Summary & Technical Compliance Assessment\nGenerated: " +
                DATE_FMT.format(Instant.now()) + " | Auditor: " + (requestedBy != null ? requestedBy : "SYSTEM"), subTitleFont);
        meta.setSpacingAfter(15);
        document.add(meta);

        // Section 1: Standards Compliance Matrix
        Paragraph s1 = new Paragraph("1. Regulatory & Standards Alignment", h2Font);
        s1.setSpacingBefore(10);
        s1.setSpacingAfter(8);
        document.add(s1);

        PdfPTable compTable = new PdfPTable(3);
        compTable.setWidthPercentage(100);
        compTable.setWidths(new float[]{2.5f, 4.0f, 1.5f});

        String[] compHeaders = {"Standard / Requirement", "Implementation Details", "Compliance Status"};
        for (String h : compHeaders) {
            PdfPCell c = new PdfPCell(new Phrase(h, headerFont));
            c.setBackgroundColor(new Color(33, 37, 41));
            c.setPadding(6);
            compTable.addCell(c);
        }

        addTableCell(compTable, "RFC 5280 X.509 v3", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        addTableCell(compTable, "Standard certificate extensions (SKI, AKI, KeyUsage, EKU, SAN)", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        addTableCell(compTable, "COMPLIANT", bodyFont, new Color(209, 231, 221), Element.ALIGN_CENTER);

        addTableCell(compTable, "RFC 6960 OCSP Responder", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        addTableCell(compTable, "Real-time revocation status validation with cached responses", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        addTableCell(compTable, "COMPLIANT", bodyFont, new Color(209, 231, 221), Element.ALIGN_CENTER);

        addTableCell(compTable, "RFC 5280 CRL / Delta CRL", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        addTableCell(compTable, "Automated scheduled regeneration & Multi-channel publishing", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        addTableCell(compTable, "COMPLIANT", bodyFont, new Color(209, 231, 221), Element.ALIGN_CENTER);

        addTableCell(compTable, "NIST SP 800-57 Key Management", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        addTableCell(compTable, "RSA >= 2048-bit, ECC (secp256r1/384r1/521r1), Ed25519", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        addTableCell(compTable, "COMPLIANT", bodyFont, new Color(209, 231, 221), Element.ALIGN_CENTER);

        addTableCell(compTable, "Audit Log Immutability", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        addTableCell(compTable, "SHA-256 chained tamper-evident blockchain-style log ledger", bodyFont, Color.WHITE, Element.ALIGN_LEFT);
        boolean chainValid = Boolean.TRUE.equals(integrity.get("valid"));
        addTableCell(compTable, chainValid ? "VERIFIED" : "ATTENTION", bodyFont,
                chainValid ? new Color(209, 231, 221) : new Color(248, 215, 218), Element.ALIGN_CENTER);

        document.add(compTable);

        // Section 2: Certificate Inventory Metrics
        Paragraph s2 = new Paragraph("2. Certificate Inventory Overview", h2Font);
        s2.setSpacingBefore(15);
        s2.setSpacingAfter(8);
        document.add(s2);

        long activeCount = certs.stream().filter(c -> "ISSUED".equalsIgnoreCase(c.getStatus()) || "ACTIVE".equalsIgnoreCase(c.getStatus())).count();
        long revokedCount = certs.stream().filter(c -> "REVOKED".equalsIgnoreCase(c.getStatus())).count();
        long subCaCount = certs.stream().filter(c -> "ROOT".equalsIgnoreCase(c.getCertificateType()) || "INTERMEDIATE".equalsIgnoreCase(c.getCertificateType())).count();

        Paragraph invText = new Paragraph(String.format(
                "• Total Managed Certificates: %d\n• Active Operational Certificates: %d\n• Revoked Certificates: %d\n• Intermediate/Root CAs: %d\n• Audit Records Chain Valid: %s",
                certs.size(), activeCount, revokedCount, subCaCount, chainValid ? "YES" : "NO"), bodyFont);
        document.add(invText);

        document.close();
        return out.toByteArray();
    }

    /**
     * Generates CSV export for Certificate Inventory.
     */
    @Transactional(readOnly = true)
    public String generateCertificateInventoryCsv() {
        List<CertificateEntity> certs = certificateRepository.findAll(Sort.by(Sort.Direction.DESC, "id"));
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);

        pw.println("Id,SerialNumber,SubjectDN,IssuerDN,Status,CertificateType,NotBefore,NotAfter,ProfileName");

        for (CertificateEntity c : certs) {
            pw.printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"%n",
                    c.getId() != null ? c.getId() : "",
                    escapeCsv(c.getSerialNumber()),
                    escapeCsv(c.getSubjectDN()),
                    escapeCsv(c.getIssuerDN()),
                    escapeCsv(c.getStatus()),
                    escapeCsv(c.getCertificateType()),
                    c.getNotBefore() != null ? c.getNotBefore().toString() : "",
                    c.getNotAfter() != null ? c.getNotAfter().toString() : "",
                    c.getProfileName() != null ? escapeCsv(c.getProfileName()) : "");
        }
        pw.flush();
        return sw.toString();
    }

    private void addTableCell(PdfPTable table, String text, Font font, Color bgColor, int alignment) {
        PdfPCell cell = new PdfPCell(new Phrase(text != null ? text : "", font));
        cell.setBackgroundColor(bgColor);
        cell.setPadding(5);
        cell.setHorizontalAlignment(alignment);
        cell.setVerticalAlignment(Element.ALIGN_MIDDLE);
        table.addCell(cell);
    }

    private void addStatCell(PdfPTable table, String label, String value, Color valueColor, Font labelFont, Font statFont) {
        PdfPCell cell = new PdfPCell();
        cell.setPadding(8);
        cell.setBackgroundColor(new Color(248, 249, 250));
        cell.setHorizontalAlignment(Element.ALIGN_CENTER);

        Paragraph val = new Paragraph(value, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, valueColor));
        val.setAlignment(Element.ALIGN_CENTER);
        Paragraph lbl = new Paragraph(label, labelFont);
        lbl.setAlignment(Element.ALIGN_CENTER);

        cell.addElement(val);
        cell.addElement(lbl);
        table.addCell(cell);
    }

    private String abbreviate(String str, int maxLen) {
        if (str == null) return "";
        if (str.length() <= maxLen) return str;
        return str.substring(0, maxLen - 3) + "...";
    }

    private String escapeCsv(String str) {
        if (str == null) return "";
        return str.replace("\"", "\"\"");
    }
}
