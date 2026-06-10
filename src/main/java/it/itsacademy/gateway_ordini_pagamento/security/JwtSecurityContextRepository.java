package it.itsacademy.gateway_ordini_pagamento.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Key;

/**
 * Chargé par Spring WebFlux Security AVANT la vérification des autorizations.
 * Lit le Bearer token, valide le JWT et peuple le SecurityContext avec
 * l'Authentication (username + rôles) — ce qui permet à hasAuthority() de fonctionner.
 */
@Component
public class JwtSecurityContextRepository implements ServerSecurityContextRepository {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Override
    public Mono<Void> save(ServerWebExchange exchange, SecurityContext context) {
        // Stateless : on ne sauvegarde rien côté serveur
        return Mono.empty();
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return Mono.empty(); // Pas de token → contexte vide → Spring Security appliquera ses règles
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            String rolesString = claims.get("roles", String.class); // ex: "ROLE_USER"

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    AuthorityUtils.commaSeparatedStringToAuthorityList(rolesString)
            );

            return Mono.just(new SecurityContextImpl(authentication));

        } catch (Exception e) {
            // Token invalide ou expiré → contexte vide → Spring Security retournera 401
            return Mono.empty();
        }
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
