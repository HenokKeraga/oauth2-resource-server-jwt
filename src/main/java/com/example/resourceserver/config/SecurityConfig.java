package com.example.resourceserver.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,
                                                   AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) throws Exception {

        httpSecurity
                .authorizeHttpRequests(a -> a.anyRequest().authenticated());
//        httpSecurity
//                .oauth2ResourceServer(configurer -> configurer.jwt(jwtConfigurer -> jwtConfigurer.jwkSetUri("http://localhost:8080/oauth2/jwks")));

        httpSecurity.oauth2ResourceServer(configurer -> configurer.authenticationManagerResolver(authenticationManagerResolver));
        httpSecurity
                .cors(httpSecurityCorsConfigurer -> {
                    var c = new CorsConfigurationSource() {
                        @Override
                        public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                            var configuration = new CorsConfiguration();
                            configuration.setAllowedOrigins(List.of("*"));
                            configuration.setAllowedMethods(List.of("*"));
                            configuration.setAllowedHeaders(List.of("*"));
                            return configuration;
                        }
                    };

                    httpSecurityCorsConfigurer.configurationSource(c);
                });

        return httpSecurity.build();
    }

//    @Bean
//    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
//
//        JwtIssuerAuthenticationManagerResolver jwtIssuerAuthenticationManagerResolver =
//                JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers("http://localhost:9999", "http://localhost:8080");
//
//        return jwtIssuerAuthenticationManagerResolver;
//    }

    @Bean
    public JwtIssuerAuthenticationManagerResolver authenticationManagerResolver(@Qualifier("jwtDecoder1") JwtDecoder jwtDecoder1,
                                                                                @Qualifier("jwtDecoder2") JwtDecoder jwtDecoder2) {
        Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
        JwtAuthenticationProvider jwtAuthenticationProvider1 = new JwtAuthenticationProvider(jwtDecoder1);
        JwtAuthenticationProvider jwtAuthenticationProvider2 = new JwtAuthenticationProvider(jwtDecoder2);
//        Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();
//         jwtAuthenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);


        authenticationManagers.put("http://localhost:9999", jwtAuthenticationProvider1::authenticate);
        authenticationManagers.put("http://localhost:8080", jwtAuthenticationProvider2::authenticate);

        return new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);
    }

    @Bean
    public JwtDecoder jwtDecoder1() {

        return NimbusJwtDecoder.withJwkSetUri("http://localhost:9999/oauth2/jwks").build();
    }

    @Bean
    public JwtDecoder jwtDecoder2() {

        return NimbusJwtDecoder.withJwkSetUri("http://localhost:8080/oauth2/jwks").build();
    }

}
