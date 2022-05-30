/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.securevault.aws.common;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.aws.exception.AWSSecretCallbackHandlerException;
import org.wso2.carbon.securevault.aws.exception.AWSVaultException;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.CONFIG_FILE_PATH;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.LEGACY_PROPERTIES_PATH;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.NOVEL_PROPERTIES_PATH;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.REGEX;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.SECRET_REPOSITORIES;

/**
 * Util methods used in the AWS Vault extension.
 */
public class AWSVaultUtils {

    private static final Log log = LogFactory.getLog(AWSVaultUtils.class);

    private AWSVaultUtils() {

    }

    /**
     * Util method to get the properties based on legacy or novel method used for defining the property
     * in the configurations file.
     *
     * @param properties   Configuration properties.
     * @param propertyName Name of the required property.
     * @return Property value.
     */
    public static String getProperty(Properties properties, String propertyName) {

        String propKey = getPropKey(properties, propertyName);
        String property = properties.getProperty(propKey);
        if (StringUtils.isEmpty(property)) {
            throw new AWSVaultException("Property " + propertyName.replaceAll(REGEX, "") +
                    " has not been set in secret-conf.properties file. Cannot build AWS Secrets Client!");
        }
        return property;
    }

    /**
     * Util method to get the properties based on legacy or novel method used for defining the property in the
     * secret-conf.properties file. If a default value is passed to the method, it will return the default value instead
     * of throwing an error if the property is empty.
     *
     * @param properties   Configuration properties.
     * @param propertyName Name of the required property.
     * @param defaultValue Returns this value if property is empty.
     * @return Property value.
     */
    public static String getProperty(Properties properties, String propertyName, String defaultValue) {

        String propKey = getPropKey(properties, propertyName);
        String property = properties.getProperty(propKey);
        if (StringUtils.isEmpty(property)) {
            return defaultValue;
        }
        return property;
    }

    /**
     * Util method to return the accurate property key based on novel or legacy configuration.
     *
     * @param properties   Configuration properties.
     * @param propertyName Name of the required property.
     * @return Property Key.
     */
    private static String getPropKey(Properties properties, String propertyName) {

        String propKey;
        boolean novelFlag = StringUtils.isEmpty(properties.getProperty(SECRET_REPOSITORIES, null));
        if (novelFlag) {
            if (log.isDebugEnabled()) {
                log.debug("Properties specified in the novel method.");
            }
            propKey = NOVEL_PROPERTIES_PATH + propertyName;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Properties specified in the legacy method.");
            }
            propKey = LEGACY_PROPERTIES_PATH + propertyName;
        }
        return propKey;
    }

    /**
     * Util method to read the 'secret-conf.properties' file and create a properties object from its content.
     *
     * @return Properties properties.
     */
    @SuppressFBWarnings("PATH_TRAVERSAL_IN")
    public static Properties readPropertiesFile() {

        if (log.isDebugEnabled()) {
            log.debug("Reading configuration properties from file.");
        }

        Properties properties = new Properties();

        //Reading configurations from file.
        try (InputStream inputStream = new FileInputStream(CONFIG_FILE_PATH)) {
            properties.load(inputStream);
        } catch (IOException e) {
            throw new AWSSecretCallbackHandlerException("Error loading configurations from " + CONFIG_FILE_PATH, e);
        }
        return properties;
    }
}
