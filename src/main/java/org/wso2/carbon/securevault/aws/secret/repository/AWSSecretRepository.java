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
import org.wso2.carbon.securevault.aws.exception.AWSVaultRuntimeException;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.CipherOperationMode;
import org.wso2.securevault.DecryptionProvider;
import org.wso2.securevault.EncodingType;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ALGORITHM;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.CRLF_SANITATION_REGEX;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.DEFAULT_ALGORITHM;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ENCRYPTION_ENABLED;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ROOT_PASSWORDS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.VERSION_DELIMITER;

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
    private boolean encryptionEnabled = false;

    /**
     * Creates an AWSSecretRepository object. This constructor is invoked when the legacy configuration has been used.
     *
     * @param identityKeyStoreWrapper Identity keystore wrapper.
     * @param trustKeyStoreWrapper    Trust keystore wrapper.
     */
    public AWSSecretRepository(IdentityKeyStoreWrapper identityKeyStoreWrapper,
                               TrustKeyStoreWrapper trustKeyStoreWrapper) {

        this.identityKeyStoreWrapper = identityKeyStoreWrapper;
        this.trustKeyStoreWrapper = trustKeyStoreWrapper;
    }

    /**
     * Creates an AWSSecretRepository object. This constructor is invoked when the novel configuration has been used.
     * It is also invoked when the repository is created in the AWSSecretCallbackHandler.
     */
    public AWSSecretRepository() {

    }

    /**
     * Initializes the AWS Secret repository based on provided properties.
     *
     * @param properties Configuration properties.
     * @param id         Identifier to identify the corresponding repository and the instance.
     */
    @Override
    public void init(Properties properties, String id) {

        if (StringUtils.equals(id, ROOT_PASSWORDS)) {
            log.info("Initializing AWS Secure Vault for root password retrieval.");
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
     * @return Secret retrieved from the AWS Secrets Manager if there is any, otherwise, an empty string.
     * @see SecretRepository
     */
    @Override
    public String getSecret(String alias) {

        /*
        If an error occurred during secret retrieval such as the secret not being available or errors in parsing the
        secret reference, an empty string would be returned from this method. If a runtime exception is thrown instead,
        the Identity Server will repeatedly attempt to retrieve the secret in a loop for secrets such as
        keystore password, truststore password, etc.
        */
        String secret = "";
        try {
            if (log.isDebugEnabled()) {
                log.debug("Retrieving secret " + alias.replaceAll(CRLF_SANITATION_REGEX, "") +
                        " from AWS Vault.");
            }
            secret = retrieveSecretFromVault(alias);
            //Decrypting the secret is done only if encryption is enabled. If not, the retrieved secret is returned.
            if (encryptionEnabled) {
                secret = new String(baseCipher.decrypt(secret.trim().getBytes(StandardCharsets.UTF_8)),
                        StandardCharsets.UTF_8);
            }
        } catch (ResourceNotFoundException e) {
            log.error("Failed to retrieve secret " + alias.replaceAll(CRLF_SANITATION_REGEX, "")
                    + " from AWS Secrets Manager. Returning empty string.", e);
        } catch (AWSVaultException | SdkClientException e) {
            log.error(e.getMessage().replaceAll(CRLF_SANITATION_REGEX, ""), e);
        }

        return secret;
    }

    /**
     * Get Encrypted data. This is only supported if encryption is enabled.
     *
     * @param alias Alias of the secret.
     */
    @Override
    public String getEncryptedData(String alias) {

        String encryptedSecret = "";
        if (!encryptionEnabled) {
            throw new UnsupportedOperationException();
        }
        try {
            encryptedSecret = retrieveSecretFromVault(alias);
        } catch (AWSVaultException e) {
            log.error(e.getMessage().replaceAll(CRLF_SANITATION_REGEX, ""), e);
        }
        return encryptedSecret;
    }

    /**
     * Retrieve the secret from the AWS Secrets Manager.
     *
     * @param alias Alias of the secret.
     */
    private String retrieveSecretFromVault(String alias) throws AWSVaultException {

        SecretReference secretReference = parseSecretReference(alias);

        GetSecretValueRequest valueRequest = GetSecretValueRequest.builder()
                .secretId(secretReference.name)
                .versionId(secretReference.version)
                .build();
        GetSecretValueResponse valueResponse = secretsClient.getSecretValue(valueRequest);
        String secret = valueResponse.secretString();

        if (StringUtils.isEmpty(secret)) {
            log.warn("Secret " + secretReference.name.replaceAll(CRLF_SANITATION_REGEX, "")
                    + " is null or empty. Returning empty string");
        }
        if (log.isDebugEnabled()) {
            log.debug("Secret " + secretReference.name.replaceAll(CRLF_SANITATION_REGEX, "") +
                    " is retrieved from Vault.");
        }

        return secret;
    }

    /**
     * Util method to get the secret name and version.
     * If no secret version is set, it will return null for versionID,
     * which will return the latest version of the secret from the AWS Secrets Manager.
     *
     * @param alias The alias of the secret. It contains both the name and version of the secret being retrieved,
     *              separated by a "#" delimiter. The version is optional and can be left blank.
     * @return An array with the secret name and the secret version.
     */
    private SecretReference parseSecretReference(String alias) throws AWSVaultException {

        SecretReference secretReference;

        if (StringUtils.isEmpty(alias)) {
            throw new AWSVaultException("Secret name cannot be empty.");
        }

        if (alias.contains(VERSION_DELIMITER)) {
            if (StringUtils.countMatches(alias, VERSION_DELIMITER) == 1) {
                String[] aliasComponents = alias.split(VERSION_DELIMITER, -1);
                if (StringUtils.isEmpty(aliasComponents[0])) {
                    throw new AWSVaultException("Secret name cannot be empty.");
                }
                if (StringUtils.isEmpty(aliasComponents[1])) {
                    aliasComponents[1] = null;
                }
                secretReference = new SecretReference(aliasComponents[0], aliasComponents[1]);
            } else {
                throw new AWSVaultException("Secret with alias " + alias.replaceAll(CRLF_SANITATION_REGEX, "") +
                        " contains multiple instances of the delimiter. It should contain only one hashtag."
                );
            }
        } else {
            secretReference = new SecretReference(alias, null);
        }


        debugLogSecretVersionStatus(secretReference);
        return secretReference;
    }

    /**
     * Util method to log whether secret version is specified or not.
     *
     * @param secretReference Secret Reference object consisting of the secret name and secret version.
     */
    private void debugLogSecretVersionStatus(SecretReference secretReference) {

        if (log.isDebugEnabled()) {
            if (StringUtils.isNotEmpty(secretReference.version)) {
                log.debug("Secret version found for " + secretReference.name.replaceAll(CRLF_SANITATION_REGEX, "")
                        + ". Retrieving the specified version of secret.");
            } else {
                log.debug("Secret version not found for " + secretReference.name.replaceAll(CRLF_SANITATION_REGEX, "") +
                        ". Retrieving latest version of secret.");
            }
        }
    }

    /**
     * Method to check whether encryption has been enabled in the configurations.
     *
     * @param properties Configuration properties.
     */
    private void setEncryptionEnabled(Properties properties) {

        String encryptionEnabledPropertyString = AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED);
        if (StringUtils.isEmpty(encryptionEnabledPropertyString)) {
            log.warn("Encryption enabled property has not been set. It will be taken as false by default.");
        }
        boolean encryptionEnabledProperty = Boolean.parseBoolean(encryptionEnabledPropertyString);

        if (encryptionEnabledProperty) {
            if (identityKeyStoreWrapper == null) {
                throw new AWSVaultRuntimeException("Key Store has not been initialized and therefore unable to " +
                        "support encrypted secrets. Encrypted secrets are not supported in the novel configuration.");
            }
            if (log.isDebugEnabled()) {
                log.debug("Encryption is enabled in AWS Secure Vault.");
            }
            encryptionEnabled = true;
            initDecryptionProvider(properties);
        } else {
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

        // If an algorithm is not specified in the properties file, RSA algorithm will be used by default.
        String algorithm = AWSVaultUtils.getProperty(properties, ALGORITHM);
        if (StringUtils.isEmpty(algorithm)) {
            algorithm = DEFAULT_ALGORITHM;
        }

        //Creates a cipherInformation
        CipherInformation cipherInformation = new CipherInformation();
        cipherInformation.setAlgorithm(algorithm);
        cipherInformation.setCipherOperationMode(CipherOperationMode.DECRYPT);
        cipherInformation.setInType(EncodingType.BASE64);
        baseCipher = CipherFactory.createCipher(cipherInformation, identityKeyStoreWrapper);
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
     * Class to create a Secret Reference object which contains the name and version of a secret.
     */
    private static class SecretReference {

        private String name;
        private String version;

        SecretReference(String name, String version) {

            this.name = name;
            this.version = version;
        }
    }
}
