package com.example.jwtdemo.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    // private final String SECRET = Base64.getEncoder().encodeToString("jwtdemo".getBytes());

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
//        User user = (User) authResult.getPrincipal();
//
//        //used to sign refresh and access token
//        Algorithm algorithm = Algorithm.HMAC256(SECRET);
//
//        //create access token
//        String accessToken
//                = JWT.create()
//                    .withSubject(user.getUsername())
//                    .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
//                    .withIssuer(request.getRequestURL().toString())
//                    .withClaim("roles", user.getAuthorities().stream().map(role -> role.getAuthority()).toList())
//                    .sign(algorithm);
//
//        //create access token
//        String refreshToken
//                = JWT.create()
//                    .withSubject(user.getUsername())
//                    .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000))
//                    .withIssuer(request.getRequestURL().toString())
//                    .sign(algorithm);
//
//        response.setHeader("access_token", accessToken);
//        response.setHeader("refresh_token", refreshToken);

        super.successfulAuthentication(request, response, chain, authResult);
    }

    /**
     * @param request
     * @param response
     * @return
     * @throws AuthenticationException
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        log.info("username: {}, password: {}", username, password);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                = new UsernamePasswordAuthenticationToken(username, password);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        //return super.attemptAuthentication(request, response);
    }
}
