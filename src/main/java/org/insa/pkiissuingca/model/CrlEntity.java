package org.insa.pkiissuingca.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "crls")
public class CrlEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ca_serial_number", nullable = false)
    private String caSerialNumber;

    @Column(name = "crl_number", nullable = false)
    private String crlNumber;

    @Column(name = "scope", nullable = false)
    private String scope; // FULL or DELTA

    @Column(name = "base_crl_number")
    private String baseCrlNumber;

    @Column(name = "this_update", nullable = false)
    private Instant thisUpdate;

    @Column(name = "next_update", nullable = false)
    private Instant nextUpdate;

    @Lob
    @Column(name = "crl_pem", nullable = false, columnDefinition = "TEXT")
    private String crlPem;

    @Lob
    @Column(name = "crl_der", nullable = false, columnDefinition = "LONGBLOB")
    private byte[] crlDer;

    @Column(name = "revoked_count", nullable = false)
    private Integer revokedCount;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    public CrlEntity() {}

    public CrlEntity(Long id, String caSerialNumber, String crlNumber, String scope, String baseCrlNumber,
                     Instant thisUpdate, Instant nextUpdate, String crlPem, byte[] crlDer,
                     Integer revokedCount, Instant createdAt) {
        this.id = id;
        this.caSerialNumber = caSerialNumber;
        this.crlNumber = crlNumber;
        this.scope = scope;
        this.baseCrlNumber = baseCrlNumber;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
        this.crlPem = crlPem;
        this.crlDer = crlDer;
        this.revokedCount = revokedCount;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCaSerialNumber() {
        return caSerialNumber;
    }

    public void setCaSerialNumber(String caSerialNumber) {
        this.caSerialNumber = caSerialNumber;
    }

    public String getCrlNumber() {
        return crlNumber;
    }

    public void setCrlNumber(String crlNumber) {
        this.crlNumber = crlNumber;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getBaseCrlNumber() {
        return baseCrlNumber;
    }

    public void setBaseCrlNumber(String baseCrlNumber) {
        this.baseCrlNumber = baseCrlNumber;
    }

    public Instant getThisUpdate() {
        return thisUpdate;
    }

    public void setThisUpdate(Instant thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    public Instant getNextUpdate() {
        return nextUpdate;
    }

    public void setNextUpdate(Instant nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    public String getCrlPem() {
        return crlPem;
    }

    public void setCrlPem(String crlPem) {
        this.crlPem = crlPem;
    }

    public byte[] getCrlDer() {
        return crlDer;
    }

    public void setCrlDer(byte[] crlDer) {
        this.crlDer = crlDer;
    }

    public Integer getRevokedCount() {
        return revokedCount;
    }

    public void setRevokedCount(Integer revokedCount) {
        this.revokedCount = revokedCount;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
}
