package com.example.Refresh_token_task.models;

import com.example.Refresh_token_task.TokenType;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "tokens")
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder

public class Token {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 512)
    private String tokenHash; // SHA-256 hex of token string

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenType type;

    @Column(nullable = false, unique = true)
    private String jti; // unique ID in JWT

    @Column(nullable = false)
    private boolean expired;

    @Column(nullable = false)
    private boolean revoked;

    @Column(nullable = false)
    private Instant issuedAt;

    @Column(nullable = false)
    private Instant expiresAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

}
