package com.stockexchange.apigateway.security;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    @Autowired
    Environment env;

    public AuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {
    }
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            HttpMethod method = request.getMethod();
            String excludedRoutes = env.getProperty("gateway.excluded-routes");
            if (excludedRoutes != null && !excludedRoutes.isEmpty()) {
                List<String> excludedRoutesList = Arrays.stream(excludedRoutes.split(","))
                        .map(String::trim)
                        .toList();

                System.out.println("Excluded routes: " + excludedRoutesList);
                System.out.println("Route: " + path);

                boolean isExcluded = excludedRoutesList.stream()
                        .anyMatch(path::endsWith);
                
                if (isExcluded && method.equals(HttpMethod.POST)) {
                    System.out.println("Path excluded from JWT check: " + path);
                    return chain.filter(exchange);
                }
            }
            
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }
            String authorizationHeader =
                    request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0); 
            String jwt = authorizationHeader.replace("Bearer", "").trim();
            if (!isJwtValid(jwt)) {
                return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
            }
            return chain.filter(exchange);
        };
    }
    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;
        String subject = null;
        try {
            byte[] secretKeyBytes =
                    Base64.getEncoder().encode(env.getProperty("token.secret").getBytes());
            SecretKey key = Keys.hmacShaKeyFor(secretKeyBytes);
            JwtParser parser = Jwts.parser() .verifyWith(key) .build();
            subject = parser.parseSignedClaims(jwt).getPayload().getSubject();
        } catch (Exception ex) { returnValue = false; }
        if (subject == null || subject.isEmpty())
        { returnValue = false; }
        return returnValue;
    }
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        // Criando um objeto de resposta com o status de erro e mensagem
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        // Você pode adicionar uma mensagem de erro no corpo da resposta, se necessário
        byte[] bytes = err.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);

        // Retornando a resposta com o status de erro e mensagem
        return response.writeWith(Mono.just(buffer));
    }
}
