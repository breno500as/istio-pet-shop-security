package com.istio.pet.shop.security.service;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.istio.pet.shop.security.configuration.KeyStoreKeyFactory;
import com.istio.pet.shop.security.configuration.SecurityProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * Utilitário para geração do web token.
 * 
 * @author breno
 *
 */

@Service
@EnableConfigurationProperties(SecurityProperties.class)
public class JwtService {
	
	
	
	private SecurityProperties securityProperties;
	
	public static final String JWK_SECRETS = "pet-shop-security@istio-pet-shop-security.herokuapp.com";
	
	public static final String ID_USUARIO_LOGADO = "id";

	public static final String NOME_USUARIO_LOGADO = "nome";

	public static final String EMAIL_USUARIO_LOGADO = "email";

	public static final String PERMISSOES_USUARIO_LOGADO = "permissoes";


	/**
	 * Construtor default.
	 */
	public JwtService(SecurityProperties securityProperties) {
		this.securityProperties = securityProperties;
	}

	/**
	 * Gera o token.
	 * 
	 * @param id
	 * @param nome
	 * @param email
	 * @param permissoes
	 * @param jwtSecretKey
	 * @return
	 */

	public  String buildAuthToken(final Long id, final String nome, final String email, final List<String> permissoes) {
		try {

			final Calendar expiresAt = Calendar.getInstance();
			expiresAt.add(Calendar.HOUR, 1);
		
			final KeyPair keyPair = keyPair();
		    Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
		    
		    return JWT.create().withKeyId(JWK_SECRETS)
		    		           .withIssuer(JWK_SECRETS)
		    		           .withSubject(JWK_SECRETS)
		    		           .withIssuedAt(new Date())
		    		           .withExpiresAt(expiresAt.getTime())
					    	   .withClaim(ID_USUARIO_LOGADO, id)
							   .withClaim(NOME_USUARIO_LOGADO, nome)
							   .withClaim(EMAIL_USUARIO_LOGADO, email)
							   .withArrayClaim(PERMISSOES_USUARIO_LOGADO, permissoes != null ? permissoes.stream().toArray(String[]::new) : null)
					           .sign(algorithm);
				 
		} catch (final IllegalArgumentException e) {
			throw new RuntimeException("Erro ao criar o token de autorização");
		} catch (final JWTCreationException e) {
			throw new RuntimeException("Erro jwt ao criar o token de autorização");
		}
	}

	/**
	 * Verifica o token pela chave secreta.
	 * 
	 * @param authorizationHeaderToken
	 * @param jwtSecretKey
	 * @return
	 */

	private  DecodedJWT verifyAuthToken(final String authorizationHeaderToken) {
		try {
			
			
			
			final KeyPair keyPair = keyPair();
			final Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
			final JWTVerifier verifier = JWT.require(algorithm).build();

			return verifier.verify(authorizationHeaderToken);

		} catch (final IllegalArgumentException e) {
			throw new RuntimeException("Erro ao verificar o token de autorização");
		} catch (final TokenExpiredException e) {
			throw new RuntimeException("Token expirado");
		} catch (final JWTVerificationException e) {
			throw new RuntimeException("Token inválido");
		}
	}

	/**
	 * Recupera e instância um usuário do token.
	 * 
	 * @param authorizationHeaderToken
	 * @param jwtSecretKey
	 * @return
	 */

	public List<String> getDadosUsuarioToken(final String authorizationHeaderToken) {

		final DecodedJWT jwt = verifyAuthToken(authorizationHeaderToken);
		
		 

		final Claim claimIdUsuario = jwt.getClaim(ID_USUARIO_LOGADO);

		// Id do usuário é obrigatório no token
		if (claimIdUsuario == null) {
			throw new RuntimeException("Usuário não encontrado ou inválido.");
		}

		final List<String> dadosUsuario = new ArrayList<String>();

		dadosUsuario.add(claimIdUsuario.asLong().toString());
		dadosUsuario.add(jwt.getClaim(NOME_USUARIO_LOGADO).asString());
		dadosUsuario.add(jwt.getClaim(EMAIL_USUARIO_LOGADO).asString());

		final Claim claimPermissoes = jwt.getClaim(PERMISSOES_USUARIO_LOGADO);

		if (claimPermissoes != null) {
			dadosUsuario.add(Arrays.asList(claimPermissoes.asArray(String.class)).stream().map(s -> s).collect(Collectors.joining(",")));
		}

		return dadosUsuario;
	}
	
	private KeyPair keyPair() {
		SecurityProperties.JwtProperties jwtProperties = securityProperties.getJwt();
		return keyPair(jwtProperties, keyStoreKeyFactory(jwtProperties));
		 
	}
	
	private KeyPair keyPair(SecurityProperties.JwtProperties jwtProperties, KeyStoreKeyFactory keyStoreKeyFactory) {
		return keyStoreKeyFactory.getKeyPair(jwtProperties.getKeyPairAlias(),
				jwtProperties.getKeyPairPassword().toCharArray());
	}

	private KeyStoreKeyFactory keyStoreKeyFactory(SecurityProperties.JwtProperties jwtProperties) {
		return new KeyStoreKeyFactory(jwtProperties.getKeyStore(), jwtProperties.getKeyStorePassword().toCharArray());
	}
	
	@Bean
	public JWKSet jwkSet() {
		 
		RSAKey.Builder builder = new RSAKey.Builder((RSAPublicKey) keyPair().getPublic())
				                           .keyUse(KeyUse.SIGNATURE)
				                           .algorithm(JWSAlgorithm.RS256)
				                           .keyID(JWK_SECRETS);
		return new JWKSet(builder.build());
	}

}
