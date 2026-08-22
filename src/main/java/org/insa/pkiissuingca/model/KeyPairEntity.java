package org.insa.pkiissuingca.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;

import java.time.Instant;

@Entity
@Table(name = "key_pairs")
public class KeyPairEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(name = "algorithm", nullable = false)
    private String algorithm;

    @Column(name = "key_size")
    private Integer keySize; // optional for RSA/ECC

    @Lob
    @Column(name = "private_key_pem", nullable = false, columnDefinition = "TEXT")
    private String privateKeyPEM;

    @Lob
    @Column(name = "public_key_pem", nullable = false, columnDefinition = "TEXT")
    private String publicKeyPEM;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnore
    private User user;

    public KeyPairEntity() {}

    public KeyPairEntity(Long id, String algorithm, Integer keySize, String privateKeyPEM, String publicKeyPEM, Instant createdAt, User user) {
        this.id = id;
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.privateKeyPEM = privateKeyPEM;
        this.publicKeyPEM = publicKeyPEM;
        this.createdAt = createdAt;
        this.user = user;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public void setKeySize(Integer keySize) {
        this.keySize = keySize;
    }

    public String getPrivateKeyPEM() {
        return privateKeyPEM;
    }

    public void setPrivateKeyPEM(String privateKeyPEM) {
        this.privateKeyPEM = privateKeyPEM;
    }

    public String getPublicKeyPEM() {
        return publicKeyPEM;
    }

    public void setPublicKeyPEM(String publicKeyPEM) {
        this.publicKeyPEM = publicKeyPEM;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}