package com.strandls.authentication_utility.filter;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.pac4j.core.profile.CommonProfile;
import org.pac4j.jwt.config.signature.SecretSignatureConfiguration;
import org.pac4j.jwt.credentials.authenticator.JwtAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserValidationFilter implements MethodInterceptor {
	
	private static final Logger logger = LoggerFactory.getLogger(UserValidationFilter.class);
	
	public static final JwtAuthenticator jwtAuthenticator;
	public static final String JWT_SALT;
	
	static {
		InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream("config.properties");
		Properties properties = new Properties();
		try {
			properties.load(in);
		} catch (IOException e) {
			logger.error(e.getMessage());
		}
		JWT_SALT = properties.getProperty("jwtSalt", "12345678901234567890123456789012");
		jwtAuthenticator = new JwtAuthenticator();
		jwtAuthenticator.addSignatureConfiguration(new SecretSignatureConfiguration(JWT_SALT));
	}

	@Override
	public Object invoke(MethodInvocation invocation) throws Throwable {
		Method method = invocation.getMethod();
		if (!method.isAnnotationPresent(ValidateUser.class)) {
			invocation.proceed();
		}
		
		int parameterIndex = getRequestParameterIndex(method);
		if (parameterIndex == -1)
			return Response.status(Status.NOT_ACCEPTABLE).entity("Api end-point should have request as parameter").build();
		
		// Extract the request out of method using parameter index.
		HttpServletRequest request = (HttpServletRequest) invocation.getArguments()[parameterIndex];
		String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
			return Response.status(Status.BAD_REQUEST).entity("Missing authorization header in request").build();
		}

		// Extract token from the authorization header.
		String token = authorizationHeader.substring("Bearer".length()).trim();
		CommonProfile profile = jwtAuthenticator.validateToken(token);
		if (profile == null) {
			return Response.status(Status.UNAUTHORIZED).entity("Invalid JWT token").build();
		}
		return invocation.proceed();
	}
	
	private int getRequestParameterIndex(Method method) {
		int i = 0;
		for (Parameter parameter : method.getParameters()) {
			if (parameter.isAnnotationPresent(Context.class) && parameter.getType().equals(HttpServletRequest.class))
				return i;
			i++;
		}

		return -1;
	}

}
