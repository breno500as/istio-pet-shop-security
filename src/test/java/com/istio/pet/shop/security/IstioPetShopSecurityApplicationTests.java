package com.istio.pet.shop.security;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.istio.pet.shop.security.service.JwtService;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;

@SpringBootTest
class IstioPetShopSecurityApplicationTests {

	@Test
	void contextLoads() { 
		 assertTrue(verifyTokenByJwksUrl());
	}
	
	public static boolean verifyTokenByJwksUrl() {

		try {
			final String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJlbWFpbF91c3VhcmlvX2xvZ2FkbyI6ImJyZW5vNTAwYXNAZ21haWwuY29tIiwiaXNzIjoicGV0LXNob3Ata2V5LWlkIiwiaWRfdXN1YXJpb19sb2dhZG8iOjEsIm5vbWVfdXN1YXJpb19sb2dhZG8iOiJicmVubyIsImV4cCI6MTYwMjE3OTI1MSwicGVybWlzc29lc191c3VhcmlvX2xvZ2FkbyI6WyJBRE1JTiJdfQ.ViIC0DxiOeyUSALmssjnbPBenmvjaHTovAMzyqKWPr4wsZwKfQJNI0z2frviWr-4VUar-UNTuW714ddMqtHnNfrYk7dY3CuG7-L5FUY1vTevDOnjhQwmyYjpdDaxJdZkUPzXOV4XEx1WOSQvKW0W43-nSnWuDvyMePqEvnAGYk9aE1i-OU5Que-rnrW_phniXt6nIap_YQ_Amf71wHujB3CKcutcKKOQWOfzU9JJ-kd2eWxjK5imG2q6BqqHulwZ499j7lwcphF9FS4Yyc01cvLa2Wz9CrZApa1jv2cNBHyioCZJSoyrWkFBbwlszThGbvzboz41affVdq5JI0B8yg";

			final JwkProvider provider = new JwkProviderBuilder(new URL("https://istio-pet-shop-security.herokuapp.com/pet-shop/.well-known/jwks.json")).build();

			final Jwk jwk = provider.get(JwtService.JWK_SECRETS);

			final SignedJWT signedJWT = SignedJWT.parse(token);
			final JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) (RSAPublicKey) jwk.getPublicKey());
			return signedJWT.verify(verifier);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}

}
