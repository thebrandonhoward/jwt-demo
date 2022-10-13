package com.example.jwtdemo.rest.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
//import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Date;
import java.util.List;

@RequestMapping("/api")
@RestController
public class Hello {
    @PostMapping( path = "/echo")
    public ResponseEntity echo() {

        final String SECRET = Base64.getEncoder().encodeToString("jwtdemo".getBytes());

        //used to sign refresh and access token
        Algorithm algorithm = Algorithm.HMAC256(SECRET);

        //create access token
        String accessToken
                = JWT.create()
                .withSubject("me")
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .withIssuer("https://example.com")
                .withClaim("roles", List.of())
                .sign(algorithm);

        //create access token
        String refreshToken
                = JWT.create()
                .withSubject("refreshme")
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
                .withIssuer("https://example.com")
                .sign(algorithm);

        return ResponseEntity.ok()
                .header("access_token", accessToken)
                .header("refresh_token", refreshToken)
                .body("Success");
    }
}
