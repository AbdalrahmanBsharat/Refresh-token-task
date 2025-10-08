package com.example.Refresh_token_task.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTService {
    // This class will handle JWT token generation and validation
    @Value("${security.jwt.secret-key}")
    private  String secretKey; //go to encryption key generator
    @Value("${security.jwt.expiration}")
    private long jwtExpiration;
    @Value("${security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    public String extractUsername(String token){
        return extractClaim(token,Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);

    }
    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) //a secret used to digitally sign the JWT
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public String generateToken(UserDetails userDetails){

        return generateToken(new HashMap<>(),userDetails);
    }
    public String generateToken(Map<String, Object> extraClaims , UserDetails userDetails){
        return buildToken(extraClaims,userDetails,jwtExpiration);
    }
    public String generateRefreshToken(UserDetails userDetails){
        return buildToken(new HashMap<>(),userDetails,refreshExpiration);
    }

    private String buildToken(Map<String,Object> extraClaims,
                              UserDetails userDetails,
                              long expiration
    ){
        String jti = generateJti();
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setId(jti)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token,UserDetails userDetails){
        final String username=extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));

    }
    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }
    public Date extractExpiration (String token){
        return extractClaim(token,Claims::getExpiration);
    }
    public Date extractIssuedAt(String token) {
        return extractClaim(token, Claims::getIssuedAt);
    }
    public String generateJti() {
        return java.util.UUID.randomUUID().toString();
    }
    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }


}
