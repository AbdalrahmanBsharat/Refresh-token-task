package com.example.Refresh_token_task.config;

import com.example.Refresh_token_task.repos.TokenRepository;
import com.example.Refresh_token_task.services.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuthFilter extends OncePerRequestFilter {

    private final JWTService JwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        final String authHeader=request.getHeader("Authorization");
        final String jwt;
        final String userName;
        if (authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;

    }
        jwt=authHeader.substring(7);// bearer with the space = 7 char
        userName= JwtService.extractUsername(jwt);
        if (userName != null && org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication() == null){
            var userDetails = this.userDetailsService.loadUserByUsername(userName);
            var isTokenValid= tokenRepository.findByTokenHash(jwt)
                    .map(t->!t.isExpired() && !t.isRevoked())
                    .orElse(false);
            if (JwtService.isTokenValid(jwt,userDetails) && isTokenValid){
                var authToken
                        = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities());
                authToken.setDetails(new org.springframework.security.web.authentication.WebAuthenticationDetailsSource().buildDetails(request));
                org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            filterChain.doFilter(request,response);
        }
    }
}
