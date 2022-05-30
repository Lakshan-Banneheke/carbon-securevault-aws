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

package org.wso2.carbon.securevault.aws.secret.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.aws.common.AWSVaultUtils;
import org.wso2.carbon.securevault.aws.exception.AWSSecretCallbackHandlerException;
import org.wso2.carbon.securevault.aws.secret.repository.AWSSecretRepository;
import org.wso2.securevault.secret.AbstractSecretCallbackHandler;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.util.Properties;

import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.IDENTITY_KEY_PASSWORD_ALIAS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.IDENTITY_STORE_PASSWORD_ALIAS;

/**
 * Secret Callback handler class if keystore and primary key passwords are stored in the AWS Vault.
 */
public class AWSSecretCallbackHandler extends AbstractSecretCallbackHandler {

    private static final Log log = LogFactory.getLog(AWSSecretCallbackHandler.class);
    private static String keyStorePassword;
    private static String privateKeyPassword;

    /**
     * Handles single secret callback.
     *
     * @param singleSecretCallback A single secret callback.
     */
    @Override
    protected void handleSingleSecretCallback(SingleSecretCallback singleSecretCallback) {

        /*
        If either of the key store password or the private key password has not been retrieved, it will attempt
        to retrieve them. If both are retrieved and store in the static variables, they will not be retrieved again.
        */
        if (StringUtils.isEmpty(keyStorePassword) || StringUtils.isEmpty(privateKeyPassword)) {
            // Indicates whether the private key and the keystore password are the same or different.
            boolean sameKeyAndKeyStorePass = true;
            /*
            If the system property "key.password" is set to "true", it indicates that the private key
            password has its own value and is not the same as the keystore password.
            */
            String keyPassword = System.getProperty("key.password");
            if (keyPassword != null && keyPassword.trim().equals("true")) {
                sameKeyAndKeyStorePass = false;
            }
            readPassword(sameKeyAndKeyStorePass);
        }

        if (singleSecretCallback.getId().equals("identity.key.password")) {
            singleSecretCallback.setSecret(privateKeyPassword);
        } else if (singleSecretCallback.getId().equals("identity.store.password")) {
            singleSecretCallback.setSecret(keyStorePassword);
        }
    }

    /**
     * Reads keystore and primary key passwords from AWS Vault.
     *
     * @param sameKeyAndKeyStorePass Flag to indicate whether the keystore and primary key passwords are the same.
     */
    private void readPassword(boolean sameKeyAndKeyStorePass) {
        Properties properties = AWSVaultUtils.readPropertiesFile();

        String keyStoreAlias = properties.getProperty(IDENTITY_STORE_PASSWORD_ALIAS);
        String privateKeyAlias = properties.getProperty(IDENTITY_KEY_PASSWORD_ALIAS);

        validateProperties(sameKeyAndKeyStorePass, keyStoreAlias, privateKeyAlias);

        AWSSecretRepository awsSecretRepository = new AWSSecretRepository();
        awsSecretRepository.init(properties, "AWSSecretRepositoryForRootPassword");

        if (log.isDebugEnabled()) {
            log.debug("Retrieving root password from AWS Secret Manager.");
        }

        keyStorePassword = awsSecretRepository.getSecret(keyStoreAlias);

        if (sameKeyAndKeyStorePass) {
            privateKeyPassword = keyStorePassword;
        } else {
            privateKeyPassword = awsSecretRepository.getSecret(privateKeyAlias);
        }
    }

    private void validateProperties(boolean sameKeyAndKeyStorePass, String keyStoreAlias, String privateKeyAlias) {

        if (StringUtils.isEmpty(keyStoreAlias)) {
            throw new AWSSecretCallbackHandlerException("keystore.identity.store.alias property has not been set. " +
                    "Unable to retrieve root keystore password from AWS Secrets Manager.");
        } else if (StringUtils.isEmpty(privateKeyAlias) && !sameKeyAndKeyStorePass) {
            throw new AWSSecretCallbackHandlerException("keystore.identity.key.alias property has not been set. " +
                    "Unable to retrieve root private key from AWS Secrets Manager.");
        }
    }
}
