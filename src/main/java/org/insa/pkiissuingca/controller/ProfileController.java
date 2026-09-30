package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.model.CertificateProfileEntity;
import org.insa.pkiissuingca.repository.CertificateProfileRepository;
import org.insa.pkiissuingca.service.AuditService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/profiles")
public class ProfileController {

    @Autowired
    private CertificateProfileRepository profileRepository;

    @Autowired
    private AuditService auditService;

    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<CertificateProfileEntity>> listProfiles() {
        return ResponseEntity.ok(profileRepository.findAll());
    }

    @GetMapping("/{id}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getProfileById(@PathVariable Long id) {
        return profileRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/by-name/{name}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getProfileByName(@PathVariable String name) {
        return profileRepository.findByName(name)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN')")
    public ResponseEntity<?> createOrUpdateProfile(@RequestBody CertificateProfileEntity profile) {
        String username = getCurrentUsername();
        try {
            if (profile.getName() == null || profile.getName().trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Profile name is mandatory.");
            }
            if (profile.getValidityDays() == null || profile.getValidityDays() <= 0) {
                profile.setValidityDays(365);
            }
            if (profile.getSignatureAlgorithm() == null || profile.getSignatureAlgorithm().trim().isEmpty()) {
                profile.setSignatureAlgorithm("SHA512withRSA");
            }

            CertificateProfileEntity existing = profileRepository.findByName(profile.getName()).orElse(null);
            if (existing != null && (profile.getId() == null || !existing.getId().equals(profile.getId()))) {
                // Update existing
                profile.setId(existing.getId());
            }

            CertificateProfileEntity saved = profileRepository.save(profile);
            auditService.log(username, "SAVE_CERTIFICATE_PROFILE", "Saved Certificate Profile: " + saved.getName(), "SUCCESS", "127.0.0.1");
            return ResponseEntity.ok(saved);
        } catch (Exception e) {
            auditService.log(username, "SAVE_CERTIFICATE_PROFILE", "Error saving profile: " + e.getMessage(), "FAILURE", "127.0.0.1");
            return ResponseEntity.badRequest().body("Failed to save profile: " + e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('CA_ADMIN', 'ROLE_CA_ADMIN')")
    public ResponseEntity<?> deleteProfile(@PathVariable Long id) {
        String username = getCurrentUsername();
        try {
            CertificateProfileEntity existing = profileRepository.findById(id).orElse(null);
            if (existing == null) {
                return ResponseEntity.notFound().build();
            }
            profileRepository.delete(existing);
            auditService.log(username, "DELETE_CERTIFICATE_PROFILE", "Deleted profile ID: " + id + ", Name: " + existing.getName(), "SUCCESS", "127.0.0.1");
            return ResponseEntity.ok("Profile deleted successfully.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to delete profile: " + e.getMessage());
        }
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
