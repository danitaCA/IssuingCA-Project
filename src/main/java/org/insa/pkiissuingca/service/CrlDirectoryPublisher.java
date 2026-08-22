package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.CrlEntity;

public interface CrlDirectoryPublisher {
    /**
     * Publishes a CRL to directory services (e.g. LDAP / Active Directory).
     *
     * @param crl          The CRL entity containing DER bytes and metadata
     * @param caCommonName The Common Name of the issuing CA
     * @throws Exception if an unhandled network or binding error occurs
     */
    void publish(CrlEntity crl, String caCommonName) throws Exception;
}
