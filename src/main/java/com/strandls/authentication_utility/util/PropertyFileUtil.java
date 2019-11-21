package com.strandls.authentication_utility.util;

import java.util.Properties;

public class PropertyFileUtil {

    public static String fetchProperty(String fileName, String propertyName) {
        Properties properties = new Properties();
        String result = "";
        try {
            ClassLoader classLoader = PropertyFileUtil.class.getClassLoader();
            properties.load(classLoader.getResourceAsStream(fileName));
            result = properties.getProperty(propertyName);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            return result;
        }
    }
}