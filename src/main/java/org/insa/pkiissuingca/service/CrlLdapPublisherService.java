package org.insa.pkiissuingca.service;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ModifyRequest;
import org.insa.pkiissuingca.model.CrlEntity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URI;

@Service
public class CrlLdapPublisherService implements CrlDirectoryPublisher {

    private static final Logger log = LoggerFactory.getLogger(CrlLdapPublisherService.class);

    @Value("${pki.ldap.enabled:false}")
    private boolean ldapEnabled;

    @Value("${pki.ldap.url:ldap://localhost:389}")
    private String ldapUrl;

    @Value("${pki.ldap.bind-dn:cn=admin,dc=example,dc=com}")
    private String bindDn;

    @Value("${pki.ldap.bind-password:changeit}")
    private String bindPassword;

    @Value("${pki.ldap.crl-dn-template:cn={caCN},ou=CRLDistributionPoints,dc=example,dc=com}")
    private String crlDnTemplate;

    @Override
    public void publish(CrlEntity crl, String caCommonName) throws Exception {
        if (!ldapEnabled) {
            log.info("LDAP CRL publishing is disabled (pki.ldap.enabled=false). Skipping LDAP publish for CA: {}", caCommonName);
            return;
        }

        URI uri = new URI(ldapUrl);
        String host = uri.getHost() != null ? uri.getHost() : "localhost";
        int port = uri.getPort() != -1 ? uri.getPort() : 389;

        log.info("Connecting to LDAP server at {}:{} to publish CRL for CA: {}", host, port, caCommonName);

        try (LDAPConnection connection = new LDAPConnection(host, port)) {
            connection.bind(bindDn, bindPassword);

            String targetDn = crlDnTemplate.replace("{caCN}", caCommonName);
            Modification mod = new Modification(ModificationType.REPLACE, "certificateRevocationList;binary", crl.getCrlDer());

            connection.modify(new ModifyRequest(targetDn, mod));
            log.info("Successfully published CRL to LDAP DN: {}", targetDn);
        } catch (Exception e) {
            log.error("Failed to publish CRL to LDAP for CA: " + caCommonName, e);
            throw e;
        }
    }
}
