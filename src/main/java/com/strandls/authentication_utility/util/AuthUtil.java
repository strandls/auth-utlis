package com.strandls.authentication_utility.util;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.pac4j.core.context.Pac4jConstants;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.core.profile.definition.CommonProfileDefinition;
import org.pac4j.core.profile.jwt.JwtClaims;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.pac4j.jwt.profile.JwtGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.strandls.authentication_utility.model.Role;
import com.strandls.authentication_utility.model.User;

public class AuthUtil {

	private static final Logger logger = LoggerFactory.getLogger(AuthUtil.class);

	private static final String JWT_SALT = "jwtSalt";
	private static final String CONFIGURATION = "config.properties";

	private AuthUtil() {
	}

	public static CommonProfile getProfileFromRequest(HttpServletRequest request) {
		CommonProfile profile = null;
		try {
			String header = request.getHeader(HttpHeaders.AUTHORIZATION);
			if (header == null || !header.startsWith("Bearer ")) {
				throw new NullPointerException();
			}

			String token = header.substring("Bearer".length()).trim();
			JwtAuthenticator authenticator = new JwtAuthenticator();
			authenticator.addSignatureConfiguration(
					new SecretSignatureConfiguration(PropertyFileUtil.fetchProperty(CONFIGURATION, JWT_SALT)));
			profile = authenticator.validateToken(token);
		} catch (Exception ex) {
			logger.error(ex.getMessage());
		}
		return profile;
	}

	public static Map<String, Object> generateToken(User user, boolean refreshToken) {
		Map<String, Object> response = new HashMap<>();
		try {
			response.putAll(buildTokens(createUserProfile(user), user, refreshToken));
		} catch (Exception ex) {
			logger.error(ex.getMessage());
		}
		return response;
	}

	public static CommonProfile createUserProfile(User user) {
		if (user == null)
			return null;
		try {
			Set<Role> roles = user.getRoles();
			Set<String> strRoles = new LinkedHashSet<>();
			if (roles != null) {
				for (Role r : roles) {
					strRoles.add(r.getAuthority());
				}
			}
			String email = user.getEmail();
			String mobile = user.getMobileNumber();
			return createUserProfile(user.getId(), user.getUserName(),
					(email == null || email.isEmpty()) ? mobile : email, strRoles);
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
		return null;
	}

	public static CommonProfile createUserProfile(Long userId, String username, String email, Set<String> authorities) {
		CommonProfile profile = new CommonProfile();
		updateUserProfile(profile, userId, username, email, authorities);
		return profile;
	}

	public static void updateUserProfile(CommonProfile profile, Long userId, String username, String email,
			Set<String> authorities) {
		if (profile == null)
			return;
		profile.setId(userId.toString());
		profile.addAttribute("id", userId);
		profile.addAttribute(Pac4jConstants.USERNAME, username);
		profile.addAttribute(CommonProfileDefinition.EMAIL, email);
		profile.addAttribute(JwtClaims.EXPIRATION_TIME, JWTUtil.getAccessTokenExpiryDate());
		profile.addAttribute(JwtClaims.ISSUED_AT, new Date());
		profile.setRoles(authorities);
		for (String authority : authorities) {
			profile.addRole(authority);
		}
	}

	public static Map<String, Object> buildTokens(CommonProfile profile, User user, boolean getRefreshToken) {
		Map<String, Object> response = new HashMap<>();
		try {
			String accessToken = generateAccessToken(profile, user);
			response.put("access_token", accessToken);
			response.put("token_type", "bearer");
			response.put("timeout", JWTUtil.getAccessTokenExpiryDate());

			if (getRefreshToken) {
				String refreshToken = generateRefreshToken(profile, user);
				response.put("refresh_token", refreshToken);
			}
		} catch (Exception ex) {
			logger.error(ex.getMessage());
		}
		return response;
	}

	public static Map<String, Object> generateAccessTokenFromEmail(String email) {
		Map<String, Object> response = new HashMap<>();
		if ( email != null && !email.isEmpty()) {

			JwtGenerator<CommonProfile> generator = new JwtGenerator<>(
					new SecretSignatureConfiguration(PropertyFileUtil.fetchProperty(CONFIGURATION, JWT_SALT)));

			Map<String, Object> jwtClaims = new HashMap<>();
			jwtClaims.put("id", null);
			jwtClaims.put(JwtClaims.SUBJECT, null);
			jwtClaims.put(Pac4jConstants.USERNAME, null);
			jwtClaims.put(CommonProfileDefinition.EMAIL, email);
			jwtClaims.put(JwtClaims.SUBJECT, email + "");
			jwtClaims.put(JwtClaims.EXPIRATION_TIME, JWTUtil.getRefreshTokenExpiryDate());
			jwtClaims.put(JwtClaims.ISSUED_AT, new Date());
			response.put("access_token", generator.generate(jwtClaims));
		}

		return response;

	}

	public static CommonProfile getProfileFromToken(String token) {
		CommonProfile profile = null;
		try {
			JwtAuthenticator authenticator = new JwtAuthenticator();
			authenticator.addSignatureConfiguration(
					new SecretSignatureConfiguration(PropertyFileUtil.fetchProperty(CONFIGURATION, JWT_SALT)));
			profile = authenticator.validateToken(token);
		} catch (Exception ex) {
			logger.error(ex.getMessage());
		}
		return profile;
	}

	private static String generateAccessToken(CommonProfile profile, User user) {
		JwtGenerator<CommonProfile> generator = new JwtGenerator<>(
				new SecretSignatureConfiguration(PropertyFileUtil.fetchProperty(CONFIGURATION, JWT_SALT)));

		Set<String> roles = new HashSet<>();
		if (user.getRoles() != null) {
			user.getRoles().forEach(role -> roles.add(role.getAuthority()));
		}

		Map<String, Object> jwtClaims = new HashMap<>();
		jwtClaims.put("id", profile.getId());
		jwtClaims.put(JwtClaims.SUBJECT, profile.getId() + "");
		jwtClaims.put(Pac4jConstants.USERNAME, profile.getUsername());
		jwtClaims.put(CommonProfileDefinition.EMAIL,
				(profile.getEmail() == null || profile.getEmail().isEmpty()) ? "" : profile.getEmail());
		jwtClaims.put(JwtClaims.EXPIRATION_TIME, JWTUtil.getAccessTokenExpiryDate());
		jwtClaims.put(JwtClaims.ISSUED_AT, new Date());
		jwtClaims.put("roles", roles);
		return generator.generate(jwtClaims);
	}

	private static String generateRefreshToken(CommonProfile profile, User user) {
		JwtGenerator<CommonProfile> generator = new JwtGenerator<>(
				new SecretSignatureConfiguration(PropertyFileUtil.fetchProperty(CONFIGURATION, JWT_SALT)));

		Set<String> roles = new HashSet<>();
		if (user.getRoles() != null) {
			user.getRoles().forEach(role -> roles.add(role.getAuthority()));
		}

		Map<String, Object> jwtClaims = new HashMap<>();
		jwtClaims.put("id", profile.getId());
		jwtClaims.put(JwtClaims.SUBJECT, profile.getId() + "");
		jwtClaims.put(Pac4jConstants.USERNAME, profile.getUsername());
		jwtClaims.put(CommonProfileDefinition.EMAIL,
				(profile.getEmail() == null || profile.getEmail().isEmpty()) ? "" : profile.getEmail());
		jwtClaims.put(JwtClaims.EXPIRATION_TIME, JWTUtil.getRefreshTokenExpiryDate());
		jwtClaims.put(JwtClaims.ISSUED_AT, new Date());
		jwtClaims.put("roles", roles);
		return generator.generate(jwtClaims);
	}

}
