package com.example.resourceserver.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        httpSecurity
                .authorizeHttpRequests(a -> a.anyRequest().authenticated());
        httpSecurity
                .oauth2ResourceServer(configurer -> configurer.jwt(jwtConfigurer -> jwtConfigurer.jwkSetUri("http://localhost:8080/oauth2/jwks")));
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
}
