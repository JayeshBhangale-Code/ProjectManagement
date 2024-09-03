package com.zosh.config;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class AppConfig {
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	    http.sessionManagement(management -> management.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
	        .authorizeHttpRequests(authorize -> authorize
	            .requestMatchers(HttpMethod.OPTIONS, "/auth/**").permitAll()  // Allow OPTIONS requests for /auth/**
	            .requestMatchers("/api/admin/**").hasRole("ADMIN")  // Restrict to ADMIN role
	            .requestMatchers("/api/**").authenticated()  // Require authentication for /api/**
	            .requestMatchers("/auth/**").permitAll()  // Permit all requests to /auth/**
	            .anyRequest().permitAll())  // Allow all other requests
	        .addFilterBefore(new JwtTokenValidator(), BasicAuthenticationFilter.class)
	        .csrf(csrf -> csrf.disable())
	        .cors(cors -> cors.configurationSource(corsConfigurationSource()));

	    return http.build();
	}



	private CorsConfigurationSource corsConfigurationSource() {
	    CorsConfiguration cfg = new CorsConfiguration();
	    
	    // Allow specific origins
	    cfg.setAllowedOrigins(Arrays.asList(
	            "http://localhost:3000",
	            "http://localhost:5173",
	            "https://project-management-solutions.firebaseapp.com"));
	    
	    // Allow all methods (GET, POST, OPTIONS, etc.)
	    cfg.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
	    
	    // Allow credentials (cookies, authorization headers)
	    cfg.setAllowCredentials(true);
	    
	    // Allow all headers
	    cfg.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept"));
	    
	    // Expose specific headers
	    cfg.setExposedHeaders(Arrays.asList("Authorization"));
	    
	    // Set max age of CORS preflight requests cache
	    cfg.setMaxAge(3600L);
	    
	    return request -> cfg;
	}

	
	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	} 


}
