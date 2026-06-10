package it.itsacademy.gateway_ordini_pagamento.security;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

/**
 * GatewayFilter qui s'exécute APRÈS la vérification des autorisations par Spring Security.
 * Sa seule responsabilité : propager les infos de l'utilisateur connecté
 * aux microservices downstream via les headers X-User-Id et X-User-Roles.
 *
 * La validation JWT est désormais gérée par JwtSecurityContextRepository.
 */
@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    public static class Config { }

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .flatMap(authentication -> {
                    ServerHttpRequest mutatedRequest = buildMutatedRequest(exchange.getRequest(), authentication);
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                // Si pas de contexte (route publique passée ici par erreur), on continue quand même
                .switchIfEmpty(chain.filter(exchange));
    }

    private ServerHttpRequest buildMutatedRequest(ServerHttpRequest request, Authentication authentication) {
        String username = authentication.getName(); // le subject du JWT

        String roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return request.mutate()
                .header("X-User-Id", username)
                .header("X-User-Roles", roles)
                .build();
    }
}