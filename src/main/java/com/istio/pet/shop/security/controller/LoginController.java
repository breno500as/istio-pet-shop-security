package com.istio.pet.shop.security.controller;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.istio.pet.shop.security.entity.Usuario;
import com.istio.pet.shop.security.service.JwtService;

@RestController
@RequestMapping("login")
public class LoginController {
	
	@Autowired
	private JwtService jwtService;

	@PostMapping
	public ResponseEntity<String> login(@RequestBody Usuario usuario) {
		return ResponseEntity.ok(this.jwtService.buildAuthToken(1L, "breno", "breno500as@gmail.com", Arrays.asList("ADMIN")));
	}

}
