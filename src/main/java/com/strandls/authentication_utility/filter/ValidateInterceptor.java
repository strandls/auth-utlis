/**
 * 
 */
package com.strandls.authentication_utility.filter;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.aopalliance.intercept.ConstructorInterceptor;
import org.aopalliance.intercept.MethodInterceptor;
import org.glassfish.hk2.api.Filter;
import org.glassfish.hk2.api.InterceptionService;

/**
 * @author Abhishek Rudra
 *
 */
public class ValidateInterceptor implements InterceptionService {

	@Override
	public Filter getDescriptorFilter() {
		return d -> d.getImplementation().startsWith("com");
	}

	@Override
	public List<MethodInterceptor> getMethodInterceptors(Method method) {
		if (method.isAnnotationPresent(ValidateUser.class)) {
			return Collections.singletonList(new UserValidationFilter());
		}
		return new ArrayList<>();
	}

	@Override
	public List<ConstructorInterceptor> getConstructorInterceptors(Constructor<?> constructor) {
		return new ArrayList<>();
	}

}
