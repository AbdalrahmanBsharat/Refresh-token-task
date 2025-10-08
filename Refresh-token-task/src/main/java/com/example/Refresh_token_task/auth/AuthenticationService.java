package com.example.Refresh_token_task.auth;

import com.example.Refresh_token_task.TokenType;
import com.example.Refresh_token_task.models.Token;
import com.example.Refresh_token_task.models.User;
import com.example.Refresh_token_task.repos.TokenRepository;
import com.example.Refresh_token_task.repos.UserRepository;
import com.example.Refresh_token_task.services.JWTService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();
        var savedUser = repository.save(user);
        var accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUsertoken(savedUser, accessToken, TokenType.ACCESS);
        saveUsertoken(savedUser, refreshToken, TokenType.REFRESH);
        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveUsertoken(User user, String jwtToken,TokenType type) {
        var token = Token.builder()
                .user(user)
                .tokenHash(jwtToken)
                .type(type)
                .expired(false)
                .revoked(false)
                .issuedAt(jwtService.extractIssuedAt(jwtToken).toInstant())
                .expiresAt(jwtService.extractExpiration(jwtToken).toInstant())
                .jti(jwtService.extractJti(jwtToken))
                .build();
        tokenRepository.save(token);
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(), // Use username, not email
                        request.getPassword()
                )
        );
        var user = repository.findByUsername(request.getUsername()).orElseThrow();
        var accessToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUsertoken(user, accessToken, TokenType.ACCESS);
        saveUsertoken(user, refreshToken, TokenType.REFRESH);

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Missing or invalid Authorization header\"}");
            return;
        }
        final String oldRefreshToken = authHeader.substring(7);
        final String username = jwtService.extractUsername(oldRefreshToken);

        if (username == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Invalid token\"}");
            return;
        }

        var user = repository.findByUsername(username).orElse(null);
        if (user == null || !jwtService.isTokenValid(oldRefreshToken, user)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Invalid or expired refresh token\"}");
            return;
        }
        revokeAllUserTokens(user);
        var newAccessToken = jwtService.generateToken(user);
        var newRefreshToken = jwtService.generateRefreshToken(user);
        saveUsertoken(user, newAccessToken, TokenType.ACCESS);
        saveUsertoken(user, newRefreshToken, TokenType.REFRESH);
        var authResponse = AuthenticationResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
    }
}