package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.model.CrlEntity;
import org.insa.pkiissuingca.repository.CrlRepository;
import org.insa.pkiissuingca.service.CrlPublisherService;
import org.insa.pkiissuingca.service.CrlService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/crl")
public class CrlController {

    private static final String PKIX_CRL_MEDIA_TYPE = "application/pkix-crl";

    @Autowired
    private CrlService crlService;

    @Autowired
    private CrlPublisherService crlPublisherService;

    @Autowired
    private CrlRepository crlRepository;

    /**
     * Get the latest FULL CRL metadata in JSON format.
     */
    @GetMapping("/{caSerialNumber}/latest")
    // @PreAuthorize("permitAll()")
    public ResponseEntity<?> getLatestFullCrl(@PathVariable String caSerialNumber) {
        CrlEntity crl = crlService.getLatestCrl(caSerialNumber, "FULL");
        if (crl == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(crl);
    }

    /**
     * Get the latest FULL CRL in binary DER format (Content-Type: application/pkix-crl).
     */
    @GetMapping(value = "/{caSerialNumber}/latest/der", produces = PKIX_CRL_MEDIA_TYPE)
    // @PreAuthorize("permitAll()")
    public ResponseEntity<byte[]> getLatestFullCrlDer(@PathVariable String caSerialNumber) {
        CrlEntity crl = crlService.getLatestCrl(caSerialNumber, "FULL");
        if (crl == null || crl.getCrlDer() == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, PKIX_CRL_MEDIA_TYPE)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + caSerialNumber + ".crl\"")
                .body(crl.getCrlDer());
    }

    /**
     * Get the latest DELTA CRL metadata in JSON format.
     */
    @GetMapping("/{caSerialNumber}/delta")
    // @PreAuthorize("permitAll()")
    public ResponseEntity<?> getLatestDeltaCrl(@PathVariable String caSerialNumber) {
        CrlEntity crl = crlService.getLatestCrl(caSerialNumber, "DELTA");
        if (crl == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(crl);
    }

    /**
     * Get the latest DELTA CRL in binary DER format (Content-Type: application/pkix-crl).
     */
    @GetMapping(value = "/{caSerialNumber}/delta/der", produces = PKIX_CRL_MEDIA_TYPE)
    // @PreAuthorize("permitAll()")
    public ResponseEntity<byte[]> getLatestDeltaCrlDer(@PathVariable String caSerialNumber) {
        CrlEntity crl = crlService.getLatestCrl(caSerialNumber, "DELTA");
        if (crl == null || crl.getCrlDer() == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, PKIX_CRL_MEDIA_TYPE)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + caSerialNumber + "-delta.crl\"")
                .body(crl.getCrlDer());
    }

    /**
     * Manually trigger regeneration and publishing of a Full CRL.
     */
    @PostMapping("/{caSerialNumber}/regenerate")
    // @PreAuthorize("hasRole('ROLE_CA_ADMIN')")
    public ResponseEntity<?> regenerateCrl(@PathVariable String caSerialNumber) {
        String username = getCurrentUsername();
        try {
            CrlEntity crl = crlService.generateFullCrl(caSerialNumber, username);
            crlPublisherService.publish(crl);
            return ResponseEntity.ok(crl);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to regenerate CRL: " + e.getMessage());
        }
    }

    /**
     * Returns the full CRL history for the specified CA.
     */
    @GetMapping("/{caSerialNumber}/history")
    // @PreAuthorize("hasAnyRole('ROLE_CA_ADMIN', 'ROLE_AUDITOR')")
    public ResponseEntity<List<CrlEntity>> getCrlHistory(@PathVariable String caSerialNumber) {
        return ResponseEntity.ok(crlRepository.findByCaSerialNumberOrderByCrlNumberDesc(caSerialNumber));
    }

    private String getCurrentUsername() {
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            return "admin";
        }
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (principal == null) {
            return "admin";
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
