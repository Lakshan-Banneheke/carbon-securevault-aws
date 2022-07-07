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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Properties;

import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.CRLF_SANITATION_REGEX;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.LEGACY_PROPERTIES_PREFIX;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.NOVEL_PROPERTIES_PREFIX;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.SECRET_REPOSITORIES;

/**
 * Util methods used in the AWS Vault extension.
 */
public class AWSVaultUtils {

    private static final Log log = LogFactory.getLog(AWSVaultUtils.class);
    private static String propertiesPrefix;

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

        if (properties == null) {
            throw new IllegalArgumentException("Properties cannot be null.");
        }
        String propKey = getPropKey(properties, propertyName);
        String property = properties.getProperty(propKey);
        if (StringUtils.isEmpty(property)) {
            log.warn("Property " + propertyName.replaceAll(CRLF_SANITATION_REGEX, "") +
                    " has not been set in secret-conf.properties file.");
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

        if (StringUtils.isEmpty(propertiesPrefix)) {
            /* The property "secretRepositories" will exist in secret-conf.properties file if the legacy configuration
               is used. The novelFlag is set to true if it does not exist. */
            boolean novelFlag = StringUtils.isEmpty(properties.getProperty(SECRET_REPOSITORIES, null));
            if (novelFlag) {
                if (log.isDebugEnabled()) {
                    log.debug("Properties specified in the novel method.");
                }
                propertiesPrefix = NOVEL_PROPERTIES_PREFIX;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Properties specified in the legacy method.");
                }
                propertiesPrefix = LEGACY_PROPERTIES_PREFIX;
            }
        }
        return propertiesPrefix + propertyName;
    }
}
