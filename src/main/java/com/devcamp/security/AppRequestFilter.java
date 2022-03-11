package com.devcamp.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.NoArgsConstructor;

@NoArgsConstructor
public class AppRequestFilter extends OncePerRequestFilter {

    protected String jwtSecret;

    /**
     * @param jwtSecret
     */
    public AppRequestFilter(String jwtSecret) {
	this.jwtSecret = jwtSecret;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
	    throws ServletException, IOException {

	if (request.getServletPath().equals("/login")) {
	    filterChain.doFilter(request, response);
	} else {
	    String authorizationHeader = request.getHeader("Authorization");
	    if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
		try {
		    String token = authorizationHeader.substring("Bearer ".length());
		    Algorithm algorithm = Algorithm.HMAC256(jwtSecret.getBytes());
		    JWTVerifier verifier = JWT.require(algorithm).build();
		    DecodedJWT decodedJWT = verifier.verify(token);

		    String username = decodedJWT.getSubject();
		    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
		    Collection<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
		    // add role to get permission
		    for (String role : roles) {
			authorities.add(new SimpleGrantedAuthority(role));
		    }
		    // authentication
		    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
			    username, null, authorities);
		    // hold authentication
		    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		    // continue filter
		    filterChain.doFilter(request, response);

		} catch (Exception e) {
		    response.setHeader("error", e.getMessage());
		    response.setStatus(500);
		    // tạo map để đẩy token ra fe cho đẹp
		    Map<String, String> error = new HashMap<String, String>();
		    error.put("error_message", e.getMessage());
		    response.setContentType("application/json");
		    // parse to json and turn out via response
		    new ObjectMapper().writeValue(response.getOutputStream(), error);
		}
	    } else {
		// filter request and response
		filterChain.doFilter(request, response);
	    }
	}
    }

}
