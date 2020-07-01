package com.ajeet.security.jwtsecuritydemo.model;

public class AuthenticationRequest {

	String username;
	String password;
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public AuthenticationRequest() {
		super();
		// TODO Auto-generated constructor stub
	}
	public AuthenticationRequest(String username, String password) {
		super();
		this.username = username;
		this.password = password;
	}
	
	
}
