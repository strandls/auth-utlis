/**
 * 
 */
package com.strandls.authentication_utility.filter;

import org.glassfish.hk2.api.InterceptionService;
import org.glassfish.hk2.utilities.binding.AbstractBinder;

/**
 * @author Abhishek Rudra
 *
 */
public class InterceptorModule extends AbstractBinder {

	@Override
	protected void configure() {
		bind(ValidateInterceptor.class).to(InterceptionService.class).in(javax.inject.Singleton.class);
	}

}
