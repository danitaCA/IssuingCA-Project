package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.service.ReportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDate;

@RestController
@RequestMapping("/api/v1/reports")
public class ReportController {

    @Autowired
    private ReportService reportService;

    /**
     * Download Certificate Inventory PDF Report (supports engine=jasper or engine=openpdf).
     */
    @GetMapping(value = "/certificates/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    @PreAuthorize("hasAnyRole('AUDITOR', 'ROLE_AUDITOR', 'CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR', 'SECURITY_OFFICER', 'ROLE_SECURITY_OFFICER')")
    public ResponseEntity<byte[]> getCertificateInventoryPdf(@org.springframework.web.bind.annotation.RequestParam(defaultValue = "jasper") String engine) {
        String username = getCurrentUsername();
        byte[] pdfBytes = reportService.generateCertificateInventoryPdf(username, engine);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"certificate-inventory-" + LocalDate.now() + ".pdf\"")
                .body(pdfBytes);
    }

    /**
     * Download Audit Trail & Verification PDF Report (supports engine=jasper or engine=openpdf).
     */
    @GetMapping(value = "/audit/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    @PreAuthorize("hasAnyRole('AUDITOR', 'ROLE_AUDITOR', 'CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR', 'SECURITY_OFFICER', 'ROLE_SECURITY_OFFICER')")
    public ResponseEntity<byte[]> getAuditTrailPdf(@org.springframework.web.bind.annotation.RequestParam(defaultValue = "jasper") String engine) {
        String username = getCurrentUsername();
        byte[] pdfBytes = reportService.generateAuditTrailPdf(username, engine);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"audit-trail-report-" + LocalDate.now() + ".pdf\"")
                .body(pdfBytes);
    }

    /**
     * Download Executive Compliance Assessment PDF Report.
     */
    @GetMapping(value = "/compliance/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    @PreAuthorize("hasAnyRole('AUDITOR', 'ROLE_AUDITOR', 'CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR', 'SECURITY_OFFICER', 'ROLE_SECURITY_OFFICER')")
    public ResponseEntity<byte[]> getComplianceReportPdf() {
        String username = getCurrentUsername();
        byte[] pdfBytes = reportService.generateComplianceReportPdf(username);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_PDF_VALUE)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"compliance-report-" + LocalDate.now() + ".pdf\"")
                .body(pdfBytes);
    }

    /**
     * Export Certificate Inventory as CSV.
     */
    @GetMapping(value = "/certificates/csv", produces = "text/csv")
    @PreAuthorize("hasAnyRole('AUDITOR', 'ROLE_AUDITOR', 'CA_ADMIN', 'ROLE_CA_ADMIN', 'RA_OPERATOR', 'ROLE_RA_OPERATOR', 'SECURITY_OFFICER', 'ROLE_SECURITY_OFFICER')")
    public ResponseEntity<String> getCertificateInventoryCsv() {
        String csvData = reportService.generateCertificateInventoryCsv();

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "text/csv; charset=UTF-8")
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"certificate-inventory-" + LocalDate.now() + ".csv\"")
                .body(csvData);
    }

    private String getCurrentUsername() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return "SYSTEM";
        }
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal == null) {
            return "SYSTEM";
        }
        if (principal instanceof String) {
            return (String) principal;
        }
        if (principal instanceof org.springframework.security.core.userdetails.UserDetails) {
            return ((org.springframework.security.core.userdetails.UserDetails) principal).getUsername();
        }
        return principal.toString();
    }
}
