package com.messmonitor.serviceuser.security;

import java.util.Date;

import com.messmonitor.serviceuser.service.impl.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.*;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    private final HttpServletRequest request;

    @Value("${user.app.jwtSecret}")
    private String jwtSecret;

    @Value("${user.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public JwtUtils(HttpServletRequest request) {
        this.request = request;
    }

    public String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }
    public String getExpiryFromJwt(String jwt) {
        Date expiryDate =  ((Claims)Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(this.jwtSecret)).parseClaimsJws(jwt).getBody()).getExpiration();
        return "logout successfully!";
    }

    public String getTokenWithBearerFromHeader(String headerName) {
        return this.request.getHeader(headerName);
    }

    public String parseToken(String header, String tokenType) {
        String token = "";
        if (header.startsWith(tokenType)){
            token = header.substring(7, header.length());
        }
        return token;

    }


    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}