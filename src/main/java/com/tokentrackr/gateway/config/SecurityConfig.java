package com.tokentrackr.gateway.config;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter.Mode;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final CorsConfigurationSource corsSource;

    public SecurityConfig(CorsConfigurationSource corsSource) {
        this.corsSource = corsSource;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                // CORS
                .cors(cors -> cors.configurationSource(corsSource))

                // disable CSRF
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // security headers
                .headers(headers -> headers
                        .hsts(hsts -> hsts
                                .includeSubdomains(true)
                                .maxAge(Duration.ofDays(365))
                                .preload(false)
                        )
                        .contentTypeOptions(withDefaults())
                        .frameOptions(frame -> frame.mode(Mode.SAMEORIGIN))
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self'; object-src 'none';")
                        )
                )

                // route authorization
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/login/**", "/oauth2/**", "/actuator/health").permitAll()
                        .pathMatchers("/user/**").hasAuthority("USER")
                        .pathMatchers("/admin/**").hasAuthority("ADMIN")
                        .anyExchange().authenticated()
                )

                // enable OAuth2 Login (redirect to Keycloak)
                .oauth2Client(withDefaults())
                .oauth2Login(withDefaults())

                // JWT Resource Server (validate Bearer tokens)
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(withDefaults()));

        return http.build();
    }
}