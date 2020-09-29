package com.istio.pet.shop.security.controller;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.istio.pet.shop.security.entity.Usuario;

@RestController
@RequestMapping("usuarios")
public class UsuarioController {

	@GetMapping
	public ResponseEntity<List<Usuario>> getUsuarios() {
		final List<Usuario> usuarios = new ArrayList<>();
		usuarios.add(new Usuario(1L, "Bertos"));
		usuarios.add(new Usuario(2L, "Teste"));
		return ResponseEntity.ok(usuarios);
	}

}
