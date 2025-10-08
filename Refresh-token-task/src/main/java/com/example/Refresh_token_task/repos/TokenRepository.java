package com.example.Refresh_token_task.repos;

import com.example.Refresh_token_task.TokenType;
import com.example.Refresh_token_task.models.Token;
import com.example.Refresh_token_task.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByTokenHash(String TokenHash);
//    Optional<Token> findByJti(String jti);
//    Optional<Token> findByTokenHashAndType(String tokenHash, TokenType type);
//    List<Token> findByUserAndTypeAndRevokedFalseAndExpiredFalse(User user, TokenType type);
    @Query("select t from Token t where t.user.id = :userId and (t.expired = false or t.revoked = false)")
    List<Token> findAllValidTokenByUser(Long userId);
}
