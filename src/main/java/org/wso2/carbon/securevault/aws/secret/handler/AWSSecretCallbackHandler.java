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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.aws.exception.AWSVaultRuntimeException;
import org.wso2.carbon.securevault.aws.secret.repository.AWSSecretRepository;
import org.wso2.securevault.secret.AbstractSecretCallbackHandler;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.CONFIG_FILE_PATH;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.IDENTITY_KEY_PASSWORD_ALIAS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.IDENTITY_STORE_PASSWORD_ALIAS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ROOT_PASSWORDS;

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
        to retrieve them. If both are retrieved and stored in the static variables, they will not be retrieved again.
        */
        if (StringUtils.isEmpty(keyStorePassword) || StringUtils.isEmpty(privateKeyPassword)) {
            // Indicates whether the private key and the keystore password are the same or different.
            boolean sameKeyAndKeyStorePass = true;
            /*
            If the system property "key.password" is set to "true", it indicates that the private key
            password is not the same as the keystore password.
            */
            String keyPassword = System.getProperty("key.password");
            if (keyPassword != null && keyPassword.trim().equals("true")) {
                sameKeyAndKeyStorePass = false;
            }
            retrievePassword(sameKeyAndKeyStorePass);
            if (log.isDebugEnabled()) {
                log.debug("Successfully retrieved key store password and private key password from AWS Vault.");
            }
        }

        if (singleSecretCallback.getId().equals("identity.key.password")) {
            singleSecretCallback.setSecret(privateKeyPassword);
        /* If the ID is equal to "identity.store.password", it will move to the else block.
           These two are the only possible values. */
        } else {
            singleSecretCallback.setSecret(keyStorePassword);
        }
    }

    /**
     * Gets the aliases of the keystore and primary key passwords from properties file and reads them from AWS Vault.
     *
     * @param sameKeyAndKeyStorePass Flag to indicate whether the keystore and primary key passwords are the same.
     */
    private void retrievePassword(boolean sameKeyAndKeyStorePass) {

        Properties properties = readPropertiesFile();

        String keyStoreAlias = properties.getProperty(IDENTITY_STORE_PASSWORD_ALIAS);
        if (StringUtils.isEmpty(keyStoreAlias)) {
            throw new AWSVaultRuntimeException(IDENTITY_STORE_PASSWORD_ALIAS + " property has not been set.");
        }

        AWSSecretRepository awsSecretRepository = new AWSSecretRepository();
        awsSecretRepository.init(properties, ROOT_PASSWORDS);

        keyStorePassword = awsSecretRepository.getSecret(keyStoreAlias);
        if (StringUtils.isEmpty(keyStorePassword)) {
            throw new AWSVaultRuntimeException("Error in retrieving " + IDENTITY_STORE_PASSWORD_ALIAS + " property.");
        }

        if (sameKeyAndKeyStorePass) {
            if (log.isDebugEnabled()) {
                log.debug("Same value is set to keystore password and private key password " +
                        "as they are defined as same.");
            }
            privateKeyPassword = keyStorePassword;
        } else {
            String privateKeyAlias = properties.getProperty(IDENTITY_KEY_PASSWORD_ALIAS);
            if (StringUtils.isEmpty(privateKeyAlias)) {
                throw new AWSVaultRuntimeException(IDENTITY_KEY_PASSWORD_ALIAS +
                        " property has not been set.");
            }
            privateKeyPassword = awsSecretRepository.getSecret(privateKeyAlias);
        }
    }

    /**
     * Util method to read the 'secret-conf.properties' file and create a properties object from its content.
     *
     * @return Properties properties.
     */
    @SuppressFBWarnings("PATH_TRAVERSAL_IN")
    private static Properties readPropertiesFile() {

        if (log.isDebugEnabled()) {
            log.debug("Reading configuration properties from file.");
        }

        Properties properties = new Properties();

        //Reading configurations from file.
        try (InputStream inputStream = new FileInputStream(CONFIG_FILE_PATH)) {
            properties.load(inputStream);
        } catch (IOException e) {
            throw new AWSVaultRuntimeException("Error loading configurations from " + CONFIG_FILE_PATH, e);
        }
        return properties;
    }
}
