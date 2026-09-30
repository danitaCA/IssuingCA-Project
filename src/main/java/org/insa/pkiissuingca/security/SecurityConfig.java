package org.insa.pkiissuingca.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(headers -> headers
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000)
                        )
                        .contentTypeOptions(contentType -> {})
                        .frameOptions(frame -> frame.deny())
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(authenticationEntryPoint())
                        .accessDeniedHandler(accessDeniedHandler())
                )
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints (Authentication, OCSP Responder, Public CRL distribution, Actuator health)
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        .requestMatchers("/api/v1/ocsp/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/crl/*/latest", "/api/v1/crl/*/latest/der",
                                "/api/v1/crl/*/delta", "/api/v1/crl/*/delta/der").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/certificates/*/pem",
                                "/api/v1/certificates/*/chain", "/api/v1/certificates/*/der").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                        // CA Lifecycle & Root/Intermediate initialization (Strictly CA_ADMIN)
                        .requestMatchers("/api/v1/certificates/cas/**").hasRole("CA_ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/v1/crl/*/regenerate").hasRole("CA_ADMIN")

                        // Certificate Operations (CA_ADMIN or RA_OPERATOR)
                        .requestMatchers(HttpMethod.POST, "/api/v1/certificates/sign", "/api/v1/certificates/enroll").hasAnyRole("CA_ADMIN", "RA_OPERATOR")
                        .requestMatchers(HttpMethod.POST, "/api/v1/certificates/*/renew", "/api/v1/certificates/*/renewed",
                                "/api/v1/certificates/*/suspend", "/api/v1/certificates/*/suspended",
                                "/api/v1/certificates/*/unsuspend", "/api/v1/certificates/*/unsuspended",
                                "/api/v1/certificates/*/revoke", "/api/v1/certificates/*/revoked").hasAnyRole("CA_ADMIN", "RA_OPERATOR")

                        // Profiles management (CA_ADMIN can create/delete; RA_OPERATOR, SECURITY_OFFICER, AUDITOR can view)
                        .requestMatchers(HttpMethod.GET, "/api/v1/profiles/**").hasAnyRole("CA_ADMIN", "RA_OPERATOR", "SECURITY_OFFICER", "AUDITOR")
                        .requestMatchers("/api/v1/profiles/**").hasRole("CA_ADMIN")

                        // Keys & Tokens (CA_ADMIN, RA_OPERATOR, SECURITY_OFFICER)
                        .requestMatchers("/api/v1/keys/**").hasAnyRole("CA_ADMIN", "RA_OPERATOR", "SECURITY_OFFICER")

                        // Audit & SIEM logs (AUDITOR, CA_ADMIN, SECURITY_OFFICER)
                        .requestMatchers("/api/v1/audit/**").hasAnyRole("AUDITOR", "CA_ADMIN", "SECURITY_OFFICER")

                        // Reporting engines (AUDITOR, CA_ADMIN, RA_OPERATOR, SECURITY_OFFICER)
                        .requestMatchers("/api/v1/reports/**").hasAnyRole("AUDITOR", "CA_ADMIN", "RA_OPERATOR", "SECURITY_OFFICER")

                        // All other API requests must be authenticated
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(String.format("{\"error\": \"Unauthorized\", \"message\": \"%s\"}", authException.getMessage()));
        };
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write(String.format("{\"error\": \"Forbidden\", \"message\": \"%s\"}", accessDeniedException.getMessage()));
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
