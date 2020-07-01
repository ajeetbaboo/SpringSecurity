package com.ajeet.security.jwtsecuritydemo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.ajeet.security.jwtsecuritydemo.jwtutil.JwtUtil;
import com.ajeet.security.jwtsecuritydemo.model.AuthenticationRequest;
import com.ajeet.security.jwtsecuritydemo.model.AuthenticationResponse;
import com.ajeet.security.jwtsecuritydemo.security.MyUserDetailsService;

@RestController
public class HelloResourceController {

	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	MyUserDetailsService userDetailsService;
	
	@Autowired
	JwtUtil jwtUtil;
	
	@GetMapping("/hello")
	public String helloWorld() {
		return "Hello!! World";
	}
	
	@PostMapping("/authenticate")
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception{
		
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUsername(),authenticationRequest.getPassword()));
		} catch (BadCredentialsException e) {
			throw new Exception("Incorrecct username or password",e);
			// TODO: handle exception
		}
		final UserDetails userDetails=userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
		String jwtToken=jwtUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(jwtToken));
	}
}
