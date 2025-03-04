package com.esprit.project.controllers;

import com.esprit.project.entities.User;
import com.esprit.project.security.JwtUtil;
import com.esprit.project.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    // ✅ Register a new user
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
        userService.registerUser(user.getUsername(), user.getPassword(), user.getRole());
        return ResponseEntity.ok("User registered successfully!");
    }

    // ✅ Login and get JWT Token
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody User user) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        UserDetails userDetails = userService.loadUserByUsername(user.getUsername());
        String role = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority) // Extract role as a string
                .findFirst()
                .orElse("USER"); // Default role if no role is assigned

        String token = jwtUtil.generateToken(userDetails.getUsername(), role);

        return ResponseEntity.ok(token);
    }
}
