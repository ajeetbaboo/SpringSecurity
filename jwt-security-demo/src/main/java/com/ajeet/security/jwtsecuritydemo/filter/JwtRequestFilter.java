package com.ajeet.security.jwtsecuritydemo.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ajeet.security.jwtsecuritydemo.jwtutil.JwtUtil;
import com.ajeet.security.jwtsecuritydemo.security.MyUserDetailsService;

@Component
public class JwtRequestFilter extends OncePerRequestFilter{

	@Autowired
	MyUserDetailsService userDetailsService;
	
	@Autowired
	JwtUtil jwtUtil;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		final String authorizationHeader=request.getHeader("Authorization");
		
		String userName=null;
		String jwt=null;
		if(authorizationHeader!=null && authorizationHeader.startsWith("Bearer")) {
			jwt=authorizationHeader.substring(7);
			userName=jwtUtil.extractUsername(jwt);
		}
		
		if(userName!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails userDetails=userDetailsService.loadUserByUsername(userName);
			if(jwtUtil.validateToken(jwt, userDetails)) {
				UsernamePasswordAuthenticationToken authToken=
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
				
			}
		}
		filterChain.doFilter(request, response);
	}
	
	
	
}
