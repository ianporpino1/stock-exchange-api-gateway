package com.stockexchange.apigateway.security;

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
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
    @Autowired
    Environment env;
    
    @Autowired
    JwtDecoder jwtDecoder;

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
                return onError(exchange, "No authorization header");
            }
            String authorizationHeader =
                    request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0); 
            String jwt = authorizationHeader.replace("Bearer", "").trim();
            if (!isJwtValid(jwt)) {
                return onError(exchange, "JWT token is not valid");
            }
            return chain.filter(exchange);
        };
    }
    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;
        try {
            Jwt jwtToken = jwtDecoder.decode(jwt);
        } catch (JwtException | IllegalArgumentException e) {
            returnValue = false;
        }
        return returnValue;
    }
    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        byte[] bytes = err.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }
}
