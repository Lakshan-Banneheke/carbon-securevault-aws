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

package org.wso2.carbon.securevault.aws.secret.repository;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.securevault.aws.common.AWSSecretManagerClient;
import org.wso2.carbon.securevault.aws.common.AWSVaultUtils;
import org.wso2.carbon.securevault.aws.exception.AWSVaultException;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.CipherOperationMode;
import org.wso2.securevault.DecryptionProvider;
import org.wso2.securevault.EncodingType;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.KeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ALGORITHM;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.DEFAULT_ALGORITHM;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.DELIMITER;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ENCRYPTION_ENABLED;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.KEY_STORE;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.REGEX;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.TRUSTED;

/**
 * AWS secret repository. This class is to facilitate the use of AWS Secrets Manager as an external vault
 * for the Carbon Secure Vault.
 */
public class AWSSecretRepository implements SecretRepository {

    private static final Log log = LogFactory.getLog(AWSSecretRepository.class);

    private SecretRepository parentRepository;
    // Secret Client used to retrieve secrets from AWS Secrets Manager Vault.
    private SecretsManagerClient secretsClient;
    private IdentityKeyStoreWrapper identityKeyStoreWrapper;
    private TrustKeyStoreWrapper trustKeyStoreWrapper;
    private DecryptionProvider baseCipher;
    private boolean encryptionEnabled;

    public AWSSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                               TrustKeyStoreWrapper trustKeyStoreWrapper) {

        this.identityKeyStoreWrapper = identityKeyStoreWrapper;
        this.trustKeyStoreWrapper = trustKeyStoreWrapper;
    }

    public AWSSecretRepository() {

    }

    /**
     * Initializes the AWS Secret repository based on provided properties.
     *
     * @param properties Configuration properties.
     * @param id         Identifier to identify properties related to the corresponding repository.
     */
    @Override
    public void init(Properties properties, String id) {

        if (StringUtils.equals(id, "AWSSecretRepositoryForRootPassword")) {
            log.info("Initializing AWS Secure Vault for root password retrieval.");
            encryptionEnabled = false;
        } else {
            log.info("Initializing AWS Secure Vault for secret retrieval.");
            setEncryptionEnabled(properties);
        }
        secretsClient = AWSSecretManagerClient.getInstance(properties);
    }

    /**
     * Get Secret from AWS Secrets Manager.
     *
     * @param alias Name and version of the secret being retrieved separated by a "#". The version is optional.
     * @return Secret retrieved from the AWS Secrets Manager if there is any, otherwise, alias itself.
     * @see SecretRepository
     */
    @Override
    public String getSecret(String alias) {

        if (StringUtils.isEmpty(alias)) {
            return alias;
        }

        String secret = retrieveSecretFromAWS(alias);

        if (encryptionEnabled) {
            //Decrypting the secret.
            return new String(baseCipher.decrypt(secret.trim().getBytes(StandardCharsets.UTF_8)),
                    StandardCharsets.UTF_8);
        } else {
            return secret;
        }
    }

    /**
     * Get Encrypted data. This is only supported if encryption is enabled.
     *
     * @param alias Alias of the secret.
     */
    @Override
    public String getEncryptedData(String alias) {

        if (encryptionEnabled) {
            return retrieveSecretFromAWS(alias);
        } else {
            throw new UnsupportedOperationException();
        }
    }

    /**
     * Retrieve the secret from the AWS Secrets Manager.
     *
     * @param alias Alias of the secret.
     */
    private String retrieveSecretFromAWS(String alias) {

        String secret;

        String[] versionDetails = getSecretVersion(alias);
        String secretName = versionDetails[0];
        String secretVersion = versionDetails[1];

        GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
                .secretId(secretName)
                .versionId(secretVersion)
                .build();

        GetSecretValueResponse valueResponse = secretsClient.getSecretValue(valueRequest);
        secret = valueResponse.secretString();

        if (log.isDebugEnabled()) {
            if (StringUtils.isEmpty(secret)) {
                log.debug("Empty secret found for alias '" + alias.replaceAll(REGEX, "") +
                        "' returning itself.");
                return alias;
            } else {
                log.debug("Secret " + secretName.replaceAll(REGEX, "") + " is retrieved.");
            }
        }

        return secret;
    }

    /**
     * Method to check whether encryption has been enabled in the configurations.
     *
     * @param properties Configuration properties.
     */
    private void setEncryptionEnabled(Properties properties) {

        String encryptionEnabledPropertyString = AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED);

        boolean encryptionEnabledProperty = Boolean.parseBoolean(encryptionEnabledPropertyString);

        if (encryptionEnabledProperty) {
            if (identityKeyStoreWrapper == null && trustKeyStoreWrapper == null) {
                throw new AWSVaultException("Key Store has not been initialized and therefore unable to support " +
                        "encrypted secrets. Encrypted secrets are not supported in the novel configuration. " +
                        "Either change the configuration to legacy method or set encryptionEnabled property as false.");
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Encryption is enabled in AWS Secure Vault.");
                }
                encryptionEnabled = true;
                initDecryptionProvider(properties);
            }
        } else {
            encryptionEnabled = false;
            if (log.isDebugEnabled()) {
                log.debug("Encryption is disabled in AWS Secure Vault.");
            }
        }
    }

    /**
     * Initialize the Decryption provider using the keystore if encryption is enabled for the vault.
     *
     * @param properties Configuration properties.
     */
    private void initDecryptionProvider(Properties properties) {

        //Load algorithm
        String algorithm = AWSVaultUtils.getProperty(properties, ALGORITHM, DEFAULT_ALGORITHM);

        //Load keyStore
        String keyStore = AWSVaultUtils.getProperty(properties, KEY_STORE, null);
        KeyStoreWrapper keyStoreWrapper;
        if (TRUSTED.equals(keyStore)) {
            keyStoreWrapper = trustKeyStoreWrapper;
        } else {
            keyStoreWrapper = identityKeyStoreWrapper;
        }

        //Creates a cipherInformation
        CipherInformation cipherInformation = new CipherInformation();
        cipherInformation.setAlgorithm(algorithm);
        cipherInformation.setCipherOperationMode(CipherOperationMode.DECRYPT);
        cipherInformation.setInType(EncodingType.BASE64);
        baseCipher = CipherFactory.createCipher(cipherInformation, keyStoreWrapper);
        if (log.isDebugEnabled()) {
            log.debug("Cipher has been created for decryption in AWS Secret Repository.");
        }
    }

    /**
     * Get parent repository.
     *
     * @return Parent repository.
     */
    @Override
    public SecretRepository getParent() {

        return this.parentRepository;
    }

    /**
     * Set parent repository.
     *
     * @param parent Parent secret repository.
     */
    @Override
    public void setParent(SecretRepository parent) {

        this.parentRepository = parent;
    }

    /**
     * Util method to get the secret name and version.
     * If no secret version is set, it will return null for versionID,
     * which will return the latest version of the secret from the AWS Secrets Manager.
     *
     * @param alias The alias of the secret.
     * @return An array with the secret name and the secret version.
     */
    private String[] getSecretVersion(String alias) {

        String[] aliasComponents = {alias, null};

        /*
         * Alias contains both the name and version of the secret being retrieved, separated by a "#" delimiter.
         * The version is optional and can be left blank.
         */
        if (alias.contains(DELIMITER)) {
            if (StringUtils.countMatches(alias, DELIMITER) == 1) {

                aliasComponents = alias.split(DELIMITER);

                if (aliasComponents.length == 2) {
                    if (log.isDebugEnabled()) {
                        log.debug("Secret version found for " + aliasComponents[0].replaceAll(REGEX, "") + "." +
                                " Retrieving the specified version of secret.");
                    }
                } else if (aliasComponents.length == 0) {
                    aliasComponents = new String[]{alias, null};
                    log.error("Secret alias has not been specified. " +
                            "Only the hashtag delimiter has been given as the alias");
                } else {
                    aliasComponents = new String[]{aliasComponents[0], null};
                    if (log.isDebugEnabled()) {
                        log.debug("Secret version not found for " + aliasComponents[0].replaceAll(REGEX, "") +
                                ". Retrieving latest version of secret.");
                    }

                }

            } else {
                log.error("Secret alias" + alias.replaceAll(REGEX, "") + " contains multiple instances of " +
                        "the delimiter. It should be of the format secretName#secretVersion. " +
                        "It should contain only one hashtag.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Secret version not found for " + aliasComponents[0].replaceAll(REGEX, "") +
                        ". Retrieving latest version of secret.");
            }
        }
        return aliasComponents;
    }

}
