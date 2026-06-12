package it.itsacademy.gateway_ordini_pagamento.security;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;

import java.util.Map;
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
        //[point de rencontre entre les commentaire authF-securityContext] sert uniquement à faire disparaître un avertissement du compilateur
        //il ne peut pas vérifier à la compilation que l'objet est réellement une Map<String,Object>
        //sans le waring,Le code fonctionne exactement pareil,
        //on aura juste un avertissement dans IntelliJ
        //Unchecked cast
        @SuppressWarnings("unchecked")
        Map<String, Object> details =
                (Map<String, Object>)
                        authentication.getDetails();

        String userId = details.get("userId").toString();//la string qu'on a ici doit rester la meme sur tout le projet.

        return request.mutate()
                .header("X-User-Id", userId)//envoi userid
                .header("X-User-Name", username)//envoi username  , changement  de la string car le nom etait
                .header("X-User-Roles", roles)//envoi role
                .build();
    }
}