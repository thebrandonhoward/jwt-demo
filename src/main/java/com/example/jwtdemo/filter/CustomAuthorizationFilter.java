package com.example.jwtdemo.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * Intercepts every request that comes in and looks for the token and process to
 * determine if user has access to certain resources.
 */
@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    private final String SECRET = Base64.getEncoder().encodeToString("jwtdemo".getBytes());

    /**
     * determines if user has access to the application
     * @param request
     * @param response
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh/**")) {
                filterChain.doFilter(request, response);
            }
            else {
                String authorizationHeader = request.getHeader(AUTHORIZATION);
                if(Objects.nonNull(authorizationHeader) && authorizationHeader.startsWith("Bearer ")) {
                    try {
                        String token = authorizationHeader.substring("Bearer ".length());
                        //used to sign refresh and access token
                        Algorithm algorithm = Algorithm.HMAC256(SECRET);

                        JWTVerifier jwtVerifier = JWT.require(algorithm).build();

                        DecodedJWT decodedJWT = jwtVerifier.verify(token);

                        String username = decodedJWT.getSubject();
                        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);

                        Collection<SimpleGrantedAuthority> simpleGrantedAuthorities = new ArrayList<>();

                        Stream.of(roles).forEach(role -> {
                            simpleGrantedAuthorities.add(new SimpleGrantedAuthority(role));
                        });

                        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                                = new UsernamePasswordAuthenticationToken(username, null, simpleGrantedAuthorities);

                        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                        //these filterchain calls keep the chain of events flowing to the next filter in the
                        //chain of filters
                        filterChain.doFilter(request, response);
                    }
                    catch (Exception e) {
                        log.error(e.getMessage(), e);
                        response.setHeader("error", e.getMessage());
                        response.setStatus(FORBIDDEN.value());
                        //response.sendError(FORBIDDEN.value());
                        //to return a body
                        Map<String, String> error = new HashMap<>();
                        error.put("error", e.getMessage());
                        response.setContentType(APPLICATION_JSON_VALUE);
                        new ObjectMapper().writeValue(response.getOutputStream(), error);
                    }
                }
                else {
                    filterChain.doFilter(request, response);
                }
            }
    }

}
