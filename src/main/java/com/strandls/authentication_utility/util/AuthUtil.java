package com.strandls.authentication_utility.util;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;

import org.pac4j.core.profile.CommonProfile;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthUtil {
	
	private static final Logger logger = LoggerFactory.getLogger(AuthUtil.class);

	public static CommonProfile getProfileFromRequest(HttpServletRequest request) {
		CommonProfile profile = null;
		try {
			String header = request.getHeader(HttpHeaders.AUTHORIZATION);
			if (header == null || !header.startsWith("Bearer ")) {}
			
			String token = header.substring("Bearer".length()).trim();
			JwtAuthenticator authenticator = new JwtAuthenticator();
			authenticator.addSignatureConfiguration(new SecretSignatureConfiguration(PropertyFileUtil.fetchProperty("config.properties", "jwtSalt")));
			profile = authenticator.validateToken(token);
		} catch (Exception ex) {
			logger.error(ex.getMessage());
		}	
		return profile;	
	}
	
}
