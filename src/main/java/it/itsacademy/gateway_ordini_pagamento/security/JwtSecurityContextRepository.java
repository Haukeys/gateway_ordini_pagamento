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
import java.util.HashMap;
import java.util.Map;

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

            String username = claims.getSubject();// morceau qui contien username de l'user
            String rolesString = claims.get("roles", String.class); // ex: "ROLE_USER"
            String userId = claims.get("userId", String.class);// ajout du morceau qui contient l id de l'user

            Map<String, Object> details = new HashMap<>();//[point de rencontre entre les commentaire authF-securityContext]
            // cette partie est en relation avec la partie  qui a etait ajouter dans
            // la partie authenticationFilter
            details.put("userId", userId);//Ici tu mets : exemple:"userId" -> "123e4567-e89b-12d3-a456-426614174000"
            //dans details, Ensuite dans AuthenticationFilter, pour récupérer cette valeur, il faut faire :
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    AuthorityUtils.commaSeparatedStringToAuthorityList(rolesString)
            );
            ((UsernamePasswordAuthenticationToken) authentication).setDetails(details);//En gros cette partie signifie
            //Attache ces informations supplémentaires à l'utilisateur authentifié afin qu'elles
            // soient récupérables plus tard via authentication.getDetails()


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
