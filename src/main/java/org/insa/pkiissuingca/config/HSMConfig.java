package org.insa.pkiissuingca.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.File;
import java.security.Provider;
import java.security.Security;

@Configuration
public class HSMConfig {

    @Value("${pki.hsm.cfg-path:C:/NewPKI-Project/softhsm.cfg}")
    private String configPath;

    @Bean
    public Provider pkcs11Provider() {
        try {
            Provider p = Security.getProvider("SunPKCS11");
            if (p == null) {
                System.err.println("SunPKCS11 security provider is not available in this JVM.");
                return null;
            }

            File cfgFile = new File(configPath);
            if (!cfgFile.exists()) {
                System.err.println("SoftHSM config file not found at " + configPath + ". PKCS11 provider disabled.");
                return null;
            }

            Provider configuredProvider = p.configure(configPath);
            Security.addProvider(configuredProvider);

            System.out.println("SoftHSM PKCS#11 Provider successfully initialized and registered.");
            return configuredProvider;
        } catch (Exception e) {
            System.err.println("Failed to initialize SoftHSM PKCS#11 Provider: " + e.getMessage());
            return null;
        }
    }
}