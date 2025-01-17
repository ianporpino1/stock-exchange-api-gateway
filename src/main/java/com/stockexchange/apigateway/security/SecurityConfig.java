package com.stockexchange.apigateway.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.FileCopyUtils;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class SecurityConfig {

    @Value("${jwt.public.key}")
    private Resource publicKeyResource;

    @Bean
    public JwtDecoder jwtDecoder() throws Exception {
        return NimbusJwtDecoder.withPublicKey(rsaPublicKey()).build();
    }
    private String readPublicKeyAsString() throws Exception {
        try (InputStreamReader reader = new InputStreamReader(publicKeyResource.getInputStream())) {
            return FileCopyUtils.copyToString(reader);
        }
    }

    @Bean
    public RSAPublicKey rsaPublicKey() throws Exception {
        try {
            String publicKeyContent = readPublicKeyAsString();
            String cleanKey = publicKeyContent
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] encoded = Base64.getDecoder().decode(cleanKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);

        } catch (Exception e) {
            System.err.println("Erro ao ler arquivo de chave pública: " + e.getMessage());
            e.printStackTrace();
            throw new Exception("Erro ao processar chave pública do arquivo: " + e.getMessage(), e);
        }
    }
}
