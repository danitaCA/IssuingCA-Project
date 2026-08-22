package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.dto.CertificateStatusDto;
import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.repository.CertificateRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CertificateStatusCacheService {

    private static final Logger log = LoggerFactory.getLogger(CertificateStatusCacheService.class);

    @Autowired
    private CertificateRepository certificateRepository;

    /**
     * Look up certificate status with Redis caching.
     */
    @Cacheable(value = "certStatus", key = "#serialNumber", unless = "#result == null")
    public CertificateStatusDto getCertificateStatus(String serialNumber) {
        log.debug("Cache miss for certificate status: {}", serialNumber);
        Optional<CertificateEntity> certOpt = certificateRepository.findBySerialNumber(serialNumber);
        return certOpt.map(cert -> new CertificateStatusDto(
                cert.getSerialNumber(),
                cert.getStatus(),
                cert.getRevocationReason(),
                cert.getRevocationDate(),
                cert.getNotBefore(),
                cert.getNotAfter(),
                cert.getIssuerDN(),
                cert.getSubjectDN()
        )).orElse(null);
    }

    /**
     * Evict cached certificate status upon mutation (revocation, suspension, renewal).
     */
    @CacheEvict(value = "certStatus", key = "#serialNumber")
    public void evictCertificateStatus(String serialNumber) {
        log.debug("Evicting certificate status from cache: {}", serialNumber);
    }
}
