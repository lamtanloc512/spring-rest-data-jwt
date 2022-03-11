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

import org.springframework.beans.factory.annotation.Value;
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

public class JwtRequestFilter extends UsernamePasswordAuthenticationFilter {

	@Value("${jwt.secret.key}")
	protected String jwtSecret;

	private final AuthenticationManager authenticationManager;
	/**
	 * @param authenticationManager
	 */
	public JwtRequestFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {

		String username = request.getParameter("username");
		String password = request.getParameter("password");

		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
				username, password);

		return authenticationManager.authenticate(authenticationToken);
		// ObjectMapper mapper = new ObjectMapper();
		//
		// try {
		// AppUser user = mapper.readValue(request.getReader(), AppUser.class);
		//
		// System.out.println(user);
		//
		// UsernamePasswordAuthenticationToken authenticationToken = new
		// UsernamePasswordAuthenticationToken(
		// user.getUsername(), user.getPassword());
		// return authenticationManager.authenticate(authenticationToken);
		//
		// } catch (StreamReadException e) {
		// e.printStackTrace();
		// return authenticationManager.authenticate(null);
		// } catch (DatabindException e) {
		// e.printStackTrace();
		// return authenticationManager.authenticate(null);
		// } catch (IOException e) {
		// e.printStackTrace();
		// return authenticationManager.authenticate(null);
		// }

	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain,
			Authentication authentication)
			throws IOException, ServletException {

		UserPrincipal userPrincipal = (UserPrincipal) authentication
				.getPrincipal();

		// Thuat toan ma hoa password
		Algorithm algorithm = Algorithm.HMAC256(jwtSecret.getBytes());

		// tao access_token
		String access_token = JWT.create()
				.withSubject(userPrincipal.getUsername())
				.withExpiresAt(new Date(
						System.currentTimeMillis() + 30 * 24 * 60 * 60 * 1000))
				.withIssuer(request.getRequestURL().toString())
				.withClaim("roles",
						userPrincipal.getAuthorities().stream()
								.map(GrantedAuthority::getAuthority)
								.collect(Collectors.toList()))
				.sign(algorithm);

		// tao access_token
		String refresh_token = JWT.create()
				.withSubject(userPrincipal.getUsername())
				.withExpiresAt(new Date(
						System.currentTimeMillis() + 31 * 24 * 60 * 60 * 1000))
				.withIssuer(request.getRequestURL().toString()).sign(algorithm);

		// tạo map để đẩy token ra fe cho đẹp
		Map<String, String> tokens = new HashMap<String, String>();
		tokens.put("access_token", access_token);
		tokens.put("refresh_token", refresh_token);
		response.setContentType("application/json");

		new ObjectMapper().writeValue(response.getOutputStream(), tokens);
	}

}
