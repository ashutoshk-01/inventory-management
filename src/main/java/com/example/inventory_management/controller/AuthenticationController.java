package com.example.inventory_management.controller;

import java.util.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.context.annotation.Configuration;

import com.example.inventory_management.model.LoginRequest;
import com.example.inventory_management.model.User;
import com.example.inventory_management.repository.UserRepository;

@RestController
public class AuthenticationController {

    @Autowired
    UserRepository userRepository;

    private final AuthenticationManager authenticationManager;

    public AuthenticationController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        try {
            // Create an authentication token
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    loginRequest.getEmail(), loginRequest.getPassword());

            // Authenticate the user
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // Set the authentication in the security context
            SecurityContextHolder.getContext().setAuthentication(authentication);
            String email = authentication.getName();
            Optional<User> user = userRepository.findByEmailAndActive(email, true);

            if (user.isPresent()) {
                Map<String, String> response = new HashMap<>();
                response.put("email", email);

                if (user.get().getAssigned().getName().equals("ADMIN")) {
                    response.put("role", "ADMIN");
                } else if (user.get().getAssigned().getName().startsWith("MANAGER")) {
                    response.put("role", "MANAGER");
                } else if (user.get().getAssigned().getName().startsWith("EMPLOYEE")) {
                    response.put("role", "EMPLOYEE");
                }
                return new ResponseEntity<>(response, HttpStatus.OK);
            }
            return new ResponseEntity<>("User has no valid role", HttpStatus.FORBIDDEN);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>("Invalid username or password", HttpStatus.UNAUTHORIZED);
        }
    }
}

@Configuration
class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:5173") // Your frontend URL
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}
