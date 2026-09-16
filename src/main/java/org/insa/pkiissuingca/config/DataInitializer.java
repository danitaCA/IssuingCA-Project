package org.insa.pkiissuingca.config;

import org.insa.pkiissuingca.model.Role;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.RoleRepository;
import org.insa.pkiissuingca.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.HashSet;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Create standard roles
        String[] roleNames = {"ROLE_CA_ADMIN", "ROLE_RA_OPERATOR", "ROLE_SECURITY_OFFICER", "ROLE_AUDITOR", "ROLE_END_ENTITY"};
        for (String roleName : roleNames) {
            if (roleRepository.findByName(roleName).isEmpty()) {
                Role role = new Role();
                role.setName(roleName);
                roleRepository.save(role);
            }
        }

        // Create default CA Admin user
        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("adminpassword"));
            admin.setEmail("admin@example.com");
            admin.setEnabled(true);

            Role adminRole = roleRepository.findByName("ROLE_CA_ADMIN")
                    .orElseThrow(() -> new IllegalStateException("ROLE_CA_ADMIN role not found"));
            admin.setRoles(new HashSet<>(Collections.singletonList(adminRole)));
            userRepository.save(admin);
        }

        // Create default Security Officer user
        if (userRepository.findByUsername("secofficer").isEmpty()) {
            User secofficer = new User();
            secofficer.setUsername("secofficer");
            secofficer.setPassword(passwordEncoder.encode("secofficerpassword"));
            secofficer.setEmail("secofficer@example.com");
            secofficer.setEnabled(true);

            Role secRole = roleRepository.findByName("ROLE_SECURITY_OFFICER")
                    .orElseThrow(() -> new IllegalStateException("ROLE_SECURITY_OFFICER role not found"));
            secofficer.setRoles(new HashSet<>(Collections.singletonList(secRole)));
            userRepository.save(secofficer);
        }

        // Create default Auditor user
        if (userRepository.findByUsername("auditor").isEmpty()) {
            User auditor = new User();
            auditor.setUsername("auditor");
            auditor.setPassword(passwordEncoder.encode("auditorpassword"));
            auditor.setEmail("auditor@example.com");
            auditor.setEnabled(true);

            Role auditorRole = roleRepository.findByName("ROLE_AUDITOR")
                    .orElseThrow(() -> new IllegalStateException("ROLE_AUDITOR role not found"));
            auditor.setRoles(new HashSet<>(Collections.singletonList(auditorRole)));
            userRepository.save(auditor);
        }

        // Create default RA Operator user
        if (userRepository.findByUsername("operator").isEmpty()) {
            User operator = new User();
            operator.setUsername("operator");
            operator.setPassword(passwordEncoder.encode("operatorpassword"));
            operator.setEmail("operator@example.com");
            operator.setEnabled(true);

            Role opRole = roleRepository.findByName("ROLE_RA_OPERATOR")
                    .orElseThrow(() -> new IllegalStateException("ROLE_RA_OPERATOR role not found"));
            operator.setRoles(new HashSet<>(Collections.singletonList(opRole)));
            userRepository.save(operator);
        }

        // Create default End Entity user
        if (userRepository.findByUsername("endentity").isEmpty()) {
            User endEntity = new User();
            endEntity.setUsername("endentity");
            endEntity.setPassword(passwordEncoder.encode("endentitypassword"));
            endEntity.setEmail("endentity@example.com");
            endEntity.setEnabled(true);

            Role eeRole = roleRepository.findByName("ROLE_END_ENTITY")
                    .orElseThrow(() -> new IllegalStateException("ROLE_END_ENTITY role not found"));
            endEntity.setRoles(new HashSet<>(Collections.singletonList(eeRole)));
            userRepository.save(endEntity);
        }

        // Initialize standard profiles
        if (profileRepository.findByName("RootCA").isEmpty()) {
            org.insa.pkiissuingca.model.CertificateProfileEntity rootProfile = new org.insa.pkiissuingca.model.CertificateProfileEntity();
            rootProfile.setName("RootCA");
            rootProfile.setDescription("Default Root CA Certificate Profile");
            rootProfile.setBasicConstraints(true);
            rootProfile.setPathLenConstraint(2);
            rootProfile.setValidityDays(3650);
            rootProfile.setKeyUsage("digitalSignature,keyCertSign,cRLSign");
            rootProfile.setSignatureAlgorithm("SHA512withRSA");
            profileRepository.save(rootProfile);
        }

        if (profileRepository.findByName("SubCA").isEmpty()) {
            org.insa.pkiissuingca.model.CertificateProfileEntity subCaProfile = new org.insa.pkiissuingca.model.CertificateProfileEntity();
            subCaProfile.setName("SubCA");
            subCaProfile.setDescription("Default Subordinate/Issuing CA Profile");
            subCaProfile.setBasicConstraints(true);
            subCaProfile.setPathLenConstraint(0);
            subCaProfile.setValidityDays(1825);
            subCaProfile.setKeyUsage("digitalSignature,keyCertSign,cRLSign");
            subCaProfile.setSignatureAlgorithm("SHA512withRSA");
            profileRepository.save(subCaProfile);
        }

        if (profileRepository.findByName("EnterpriseEndEntity").isEmpty()) {
            org.insa.pkiissuingca.model.CertificateProfileEntity eeProfile = new org.insa.pkiissuingca.model.CertificateProfileEntity();
            eeProfile.setName("EnterpriseEndEntity");
            eeProfile.setDescription("Standard profile for corporate users & web servers");
            eeProfile.setBasicConstraints(false);
            eeProfile.setValidityDays(365);
            eeProfile.setKeyUsage("digitalSignature,keyEncipherment");
            eeProfile.setExtendedKeyUsage("serverAuth,clientAuth,emailProtection");
            eeProfile.setSignatureAlgorithm("SHA512withRSA");
            profileRepository.save(eeProfile);
        }
    }

    @Autowired
    private org.insa.pkiissuingca.repository.CertificateProfileRepository profileRepository;
}
