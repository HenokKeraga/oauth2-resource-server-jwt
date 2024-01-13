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
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
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
        //opaque token
        //    httpSecurity.oauth2ResourceServer(configurer -> configurer.opaqueToken(opaqueTokenConfigurer -> opaqueTokenConfigurer.introspectionUri("http://localhost:8080/oauth2/introspect")));
//    jwt token
//        httpSecurity
//                .oauth2ResourceServer(configurer -> configurer.jwt(jwtConfigurer -> jwtConfigurer.jwkSetUri("http://localhost:8080/oauth2/jwks")));

        //using authentication manager resolver
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

//    @Bean
//    public JwtIssuerAuthenticationManagerResolver authenticationManagerResolver(@Qualifier("jwtDecoder1") JwtDecoder jwtDecoder1,
//                                                                                @Qualifier("jwtDecoder2") JwtDecoder jwtDecoder2) {
//        Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
//        JwtAuthenticationProvider jwtAuthenticationProvider1 = new JwtAuthenticationProvider(jwtDecoder1);
//        JwtAuthenticationProvider jwtAuthenticationProvider2 = new JwtAuthenticationProvider(jwtDecoder2);
////        Converter<Jwt, ? extends AbstractAuthenticationToken> jwtAuthenticationConverter = new JwtAuthenticationConverter();
////         jwtAuthenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
//
//
//        authenticationManagers.put("http://localhost:9999", jwtAuthenticationProvider1::authenticate);
//        authenticationManagers.put("http://localhost:8080", jwtAuthenticationProvider2::authenticate);
//
//        return new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);
//    }

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver(@Qualifier("jwtDecoder1") JwtDecoder jwtDecoder1,
                                                                                           OpaqueTokenIntrospector opaqueTokenIntrospector) {
        return new AuthenticationManagerResolver<HttpServletRequest>() {
            @Override
            public AuthenticationManager resolve(HttpServletRequest request) {
                 if(null!= request.getHeader("type")&&request.getHeader("type").equals("jwt")){
                     var jwtAuthenticationProvider = new JwtAuthenticationProvider(jwtDecoder1);

                     return authentication -> jwtAuthenticationProvider.authenticate(authentication);
                 }else {
                var opaqueTokenAuthenticationProvider = new OpaqueTokenAuthenticationProvider(opaqueTokenIntrospector);
                return new ProviderManager(opaqueTokenAuthenticationProvider);
                 }

            }
        };
    }
//for opaque token authorization server
    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector() {

        return new SpringOpaqueTokenIntrospector("http://localhost:8080/oauth2/introspect",
                "oidc-client", "secret");
    }

//for jwt token authorization server

    @Bean
    public JwtDecoder jwtDecoder1() {

        return NimbusJwtDecoder.withJwkSetUri("http://localhost:9999/oauth2/jwks").build();
    }

    @Bean
    public JwtDecoder jwtDecoder2() {

        return NimbusJwtDecoder.withJwkSetUri("http://localhost:8080/oauth2/jwks").build();
    }

}
