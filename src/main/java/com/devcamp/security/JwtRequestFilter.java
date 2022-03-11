package com.devcamp.security;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.devcamp.utils.UserPrincipal;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class JwtRequestFilter extends UsernamePasswordAuthenticationFilter {

    private String jwtSecret;

    private final AuthenticationManager authenticationManager;

    /**
     * @param authenticationManager
     * @param jwtSecret
     */
    public JwtRequestFilter(AuthenticationManager authenticationManager, String jwtSecret) {
	this.authenticationManager = authenticationManager;
	this.jwtSecret = jwtSecret;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
	    throws AuthenticationException {
	String username = request.getParameter("username");
	String password = request.getParameter("password");
	UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,
		password);
	return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
	    Authentication authentication) throws IOException, ServletException {
	UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
	// Thuat toan ma hoa password
	Algorithm algorithm = Algorithm.HMAC256(jwtSecret.getBytes());
	// tao access_token
	String access_token = JWT.create().withSubject(userPrincipal.getUsername())
		.withExpiresAt(new Date(System.currentTimeMillis() + 30 * 24 * 60 * 60 * 1000L)) // 1 thang 30 ngay
		.withIssuer(request.getRequestURL().toString()).withClaim("roles", userPrincipal.getAuthorities()
			.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
		.sign(algorithm);
	// tao access_token
	String refresh_token = JWT.create().withSubject(userPrincipal.getUsername())
		.withExpiresAt(new Date(System.currentTimeMillis() + 31 * 24 * 60 * 60 * 1000L)) // 1 thang 31 ngay
		.withIssuer(request.getRequestURL().toString()).sign(algorithm);
	// tạo map để đẩy token ra fe cho đẹp
	Map<String, String> tokens = new HashMap<String, String>();
	tokens.put("access_token", access_token);
	tokens.put("refresh_token", refresh_token);
	response.setContentType("application/json");
	new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

}
