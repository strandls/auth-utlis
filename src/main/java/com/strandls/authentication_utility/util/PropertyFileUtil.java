package com.strandls.authentication_utility.util;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PropertyFileUtil {

	private static final Logger logger = LoggerFactory.getLogger(PropertyFileUtil.class);
	
	private PropertyFileUtil() {}

	public static String fetchProperty(String fileName, String propertyName) {
		Properties properties = new Properties();
		String result = "";
		try {
			ClassLoader classLoader = PropertyFileUtil.class.getClassLoader();
			properties.load(classLoader.getResourceAsStream(fileName));
			result = properties.getProperty(propertyName);
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
		return result;
	}
}