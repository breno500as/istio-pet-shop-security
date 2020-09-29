package com.istio.pet.shop.security.controller;

import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.istio.pet.shop.security.entity.Usuario;

@RestController
@RequestMapping("login")
public class LoginController {

	@PostMapping
	public ResponseEntity<String> login(@RequestBody Usuario usuario) {
		return ResponseEntity.ok(UUID.randomUUID().toString());
	}

}
