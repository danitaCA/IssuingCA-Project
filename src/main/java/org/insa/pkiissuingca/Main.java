package org.insa.pkiissuingca;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.Security;

@SpringBootApplication
@EnableScheduling
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
    @Bean
    public CommandLineRunner initData(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            // Helper method or lambda logic for upserting users
            upsertUser(userRepository, passwordEncoder, "pki_user", "pki_pass", "user@insa.gov.et");
            upsertUser(userRepository, passwordEncoder, "pki_admin", "pki_pass", "admin@insa.gov.et");
            System.out.println("Default credentials/status verified for pki_user and pki_admin!");
        };
    }

    private void upsertUser(UserRepository userRepository, PasswordEncoder passwordEncoder, String username, String rawPassword, String email) {
        User user = userRepository.findByUsername(username).orElseGet(() -> {
            User newUser = new User();
            newUser.setUsername(username);
            newUser.setEmail(email);
            // uuid, failedLoginAttempts, isSoftDeleted, mfaEnabled, requiresPasswordChange
            // will automatically take their default field values or you can explicitly set them if needed:
            return newUser;
        });

        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setEnabled(true);
        userRepository.save(user);
    }}