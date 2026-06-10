package it.itsacademy.gateway_ordini_pagamento.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final JwtSecurityContextRepository jwtSecurityContextRepository;

    public SecurityConfig(JwtSecurityContextRepository jwtSecurityContextRepository) {
        this.jwtSecurityContextRepository = jwtSecurityContextRepository;
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(csrf -> csrf.disable())
                .httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(formLogin -> formLogin.disable())
                // Déléguer le chargement du contexte de sécurité au JwtSecurityContextRepository
                // Cela permet à Spring Security de connaître les rôles AVANT de vérifier hasAuthority()
                .securityContextRepository(jwtSecurityContextRepository)
                .authorizeExchange(exchanges -> exchanges
                        // Routes publiques : pas besoin de token
                        .pathMatchers("/api/auth/**").permitAll()
                        .pathMatchers("/error").permitAll()

                        // Seul ROLE_USER peut accéder aux ordini
                        .pathMatchers(HttpMethod.GET, "/api/ordini/**").hasAuthority("ROLE_USER")
                        .pathMatchers(HttpMethod.POST, "/api/ordini/**").hasAuthority("ROLE_USER")
                        .pathMatchers(HttpMethod.PUT, "/api/ordini/**").hasAuthority("ROLE_USER")
                        .pathMatchers(HttpMethod.DELETE, "/api/ordini/**").hasAuthority("ROLE_USER")

                        // Seul ROLE_USER peut accéder aux pagamenti
                        .pathMatchers("/api/pagamenti/**").hasAuthority("ROLE_USER")

                        // Tout le reste nécessite d'être connecté
                        .anyExchange().authenticated()
                );

        return http.build();
    }
}