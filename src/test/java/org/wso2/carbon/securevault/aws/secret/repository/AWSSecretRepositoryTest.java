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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.securevault.aws.common.AWSSecretManagerClient;
import org.wso2.carbon.securevault.aws.common.AWSVaultUtils;
import org.wso2.carbon.securevault.aws.exception.AWSVaultException;
import org.wso2.carbon.securevault.aws.exception.AWSVaultRuntimeException;
import org.wso2.securevault.AsymmetricCipher;
import org.wso2.securevault.CipherFactory;
import org.wso2.securevault.definition.CipherInformation;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;
import org.wso2.securevault.secret.SecretRepository;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ENCRYPTION_ENABLED;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.ROOT_PASSWORDS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.VERSION_DELIMITER;

/**
 * Unit test class for AWSSecretRepository.
 */
@PrepareForTest({AWSSecretRepository.class, LogFactory.class, AWSVaultUtils.class, AWSSecretManagerClient.class,
        CipherFactory.class, GetSecretValueRequest.class, GetSecretValueResponse.class})
public class AWSSecretRepositoryTest extends PowerMockTestCase {

    private Properties properties;
    private AWSSecretRepository awsSecretRepositoryRootPassword;
    private AWSSecretRepository awsSecretRepositorySecretRetrieval;
    private Log logger;
    private GetSecretValueResponse getSecretValueResponse;
    private GetSecretValueRequest.Builder getSecretValueRequestBuilder;

    @BeforeClass
    public void setUp() {

        mockStatic(LogFactory.class);
        logger = mock(Log.class);
        when(logger.isDebugEnabled()).thenReturn(true);
        when(LogFactory.getLog(AWSSecretRepository.class)).thenReturn(logger);
    }

    @BeforeMethod
    public void setUpBeforeMethod() {

        properties = new Properties();

        mockStatic(AWSVaultUtils.class);
        mockStatic(AWSSecretManagerClient.class);
        when(AWSSecretManagerClient.getInstance(properties)).thenReturn(mock(SecretsManagerClient.class));

        IdentityKeyStoreWrapper identityKeyStoreWrapper = mock(IdentityKeyStoreWrapper.class);
        TrustKeyStoreWrapper trustKeyStoreWrapper = mock(TrustKeyStoreWrapper.class);

        mock(CipherInformation.class);
        mockStatic(CipherFactory.class);

        mockStatic(GetSecretValueRequest.class);
        GetSecretValueRequest getSecretValueRequestObj = mock(GetSecretValueRequest.class);

        getSecretValueRequestBuilder = mock(GetSecretValueRequest.Builder.class);
        when(getSecretValueRequestBuilder.secretId(any())).thenReturn(getSecretValueRequestBuilder);
        when(getSecretValueRequestBuilder.versionId(any())).thenReturn(getSecretValueRequestBuilder);
        when(getSecretValueRequestBuilder.build()).thenReturn(getSecretValueRequestObj);
        when(GetSecretValueRequest.builder()).thenReturn(getSecretValueRequestBuilder);

        awsSecretRepositoryRootPassword = new AWSSecretRepository();
        awsSecretRepositorySecretRetrieval = new AWSSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper);

        SecretsManagerClient secretsClient = mock(SecretsManagerClient.class);
        getSecretValueResponse = mock(GetSecretValueResponse.class);
        when(secretsClient.getSecretValue(getSecretValueRequestObj)).thenReturn(getSecretValueResponse);
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "secretsClient", secretsClient);
    }

    @Test(description = "Test case for init() method for root password retrieval.")
    public void testInitRootPasswordRetrieval() {

        awsSecretRepositoryRootPassword.init(properties, ROOT_PASSWORDS);

        Assert.assertFalse(Whitebox.getInternalState(awsSecretRepositoryRootPassword, "encryptionEnabled"));
    }

    @Test(dataProvider = "initDataProvider",
            description = "Positive test case for init() method for secret retrieval.")
    public void testInitSecretRetrievalPositive(String encryptionEnabledConfig,
                                                Boolean encryptionEnabled) {

        when(AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn(encryptionEnabledConfig);
        awsSecretRepositorySecretRetrieval.init(properties, anyString());

        Assert.assertEquals(Whitebox.getInternalState(awsSecretRepositorySecretRetrieval, "encryptionEnabled"),
                encryptionEnabled);
    }

    @Test(description = "Negative test case for init() method for secret retrieval when encryption is enabled.")
    public void testInitEncryptedEnabledSecretRetrievalNegative() {

        when(AWSVaultUtils.getProperty(properties, ENCRYPTION_ENABLED)).thenReturn("true");
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "identityKeyStoreWrapper", (Object[]) null);

        assertThrows(
                AWSVaultRuntimeException.class,
                () -> awsSecretRepositorySecretRetrieval.init(properties, anyString())
        );
        Assert.assertFalse(Whitebox.getInternalState(awsSecretRepositorySecretRetrieval, "encryptionEnabled"));
    }

    @Test(description = "Test case for getParent() method.")
    public void testGetParent() {

        SecretRepository secretRepository = mock(SecretRepository.class);
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "parentRepository", secretRepository);

        SecretRepository parentRepository = awsSecretRepositorySecretRetrieval.getParent();
        Assert.assertSame(parentRepository, secretRepository);
    }

    @Test(description = "Test case for setParent() method.")
    public void testSetParent() {

        SecretRepository secretRepository = mock(SecretRepository.class);
        awsSecretRepositorySecretRetrieval.setParent(secretRepository);

        Assert.assertSame(
                Whitebox.getInternalState(awsSecretRepositorySecretRetrieval, "parentRepository"),
                secretRepository
        );
    }

    @Test(dataProvider = "secretDataProviderPositive",
            description = "Positive test case for getSecret() method when encryption is disabled.")
    public void testGetSecretUnencryptedPositive(String secretAlias, String secretValue) {

        String[] aliasComponents;
        if (secretAlias.contains(VERSION_DELIMITER)) {
            aliasComponents = secretAlias.split("#", -1);
        } else {
            aliasComponents = new String[]{secretAlias, null};
        }
        when(getSecretValueResponse.secretString()).thenReturn(secretValue);
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "encryptionEnabled", false);
        String retrievedSecret = awsSecretRepositorySecretRetrieval.getSecret(secretAlias);

        verify(getSecretValueRequestBuilder).secretId(aliasComponents[0]);
        if (aliasComponents[1] != null && aliasComponents[1].equals("")) {
            aliasComponents[1] = null;
        }
        verify(getSecretValueRequestBuilder).versionId(aliasComponents[1]);
        Assert.assertEquals(retrievedSecret, secretValue);
    }

    @Test(dataProvider = "secretDataProviderPositive",
            description = "Positive test case for getSecret() method when encryption is enabled.")
    public void testGetSecretEncryptedPositive(String secretAlias, String secretValue) {

        String[] aliasComponents;
        if (secretAlias.contains(VERSION_DELIMITER)) {
            aliasComponents = secretAlias.split("#", -1);
        } else {
            aliasComponents = new String[]{secretAlias, null};
        }
        AsymmetricCipher baseCipher = mock(AsymmetricCipher.class);
        when(baseCipher.decrypt(any())).thenReturn(secretValue.getBytes(StandardCharsets.UTF_8));

        when(getSecretValueResponse.secretString()).thenReturn(secretValue);
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "baseCipher", baseCipher);
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "encryptionEnabled", true);
        String retrievedSecret = awsSecretRepositorySecretRetrieval.getSecret(secretAlias);

        verify(baseCipher).decrypt(secretValue.trim().getBytes(StandardCharsets.UTF_8));
        verify(getSecretValueRequestBuilder).secretId(aliasComponents[0]);
        if (aliasComponents[1] != null && aliasComponents[1].equals("")) {
            aliasComponents[1] = null;
        }
        verify(getSecretValueRequestBuilder).versionId(aliasComponents[1]);
        Assert.assertEquals(retrievedSecret, secretValue);
    }

    @Test(description = "Test case for getSecret() method when secret value is empty.")
    public void testGetSecretEmpty() {

        when(getSecretValueResponse.secretString()).thenReturn("");
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "encryptionEnabled", false);
        String retrievedSecret = awsSecretRepositorySecretRetrieval.getSecret("testAlias");

        Assert.assertEquals(retrievedSecret, "");
    }

    @Test(dataProvider = "secretDataProviderNegative",
            description = "Negative test case for getSecret() method when encryption is disabled.")
    public void testGetSecretNegative(String secretAlias, String secretValue) {

        when(getSecretValueResponse.secretString()).thenReturn(secretValue);
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "encryptionEnabled", false);

        String retrievedSecret = awsSecretRepositorySecretRetrieval.getSecret(secretAlias);

        /*
        The exception is thrown in a private method and is caught by the public method and an error is logged.
        Therefore, we cannot assert that the exception has been thrown and due to that, the assertion is done to
        check whether the error has been logged with the required exception.
        */
        verify(logger).error(anyString(), any(AWSVaultException.class));
        Assert.assertEquals(retrievedSecret, "");
        Mockito.reset(logger);
        when(logger.isDebugEnabled()).thenReturn(true);
    }

    @Test(dataProvider = "secretDataProviderPositive",
            description = "Positive test case for getEncryptedData() method when encryption is enabled.")
    public void testGetEncryptedDataPositive(String secretAlias, String secretValue) {

        String[] aliasComponents;
        if (secretAlias.contains(VERSION_DELIMITER)) {
            aliasComponents = secretAlias.split("#", -1);
        } else {
            aliasComponents = new String[]{secretAlias, null};
        }
        when(getSecretValueResponse.secretString()).thenReturn(secretValue);
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "encryptionEnabled", true);
        String retrievedSecret = awsSecretRepositorySecretRetrieval.getEncryptedData(secretAlias);

        verify(getSecretValueRequestBuilder).secretId(aliasComponents[0]);
        if (aliasComponents[1] != null && aliasComponents[1].equals("")) {
            aliasComponents[1] = null;
        }
        verify(getSecretValueRequestBuilder).versionId(aliasComponents[1]);
        Assert.assertEquals(retrievedSecret, secretValue);
    }

    @Test(description = "Negative test case for getEncryptedData() method when encryption is disabled.")
    public void testGetEncryptedDataEncryptionDisabled() {

        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "encryptionEnabled", false);

        assertThrows(
                UnsupportedOperationException.class,
                () -> awsSecretRepositorySecretRetrieval.getEncryptedData("testAlias")
        );
    }

    @Test(dataProvider = "secretDataProviderNegative",
            description = "Negative test case for getEncryptedData() method when encryption is disabled.")
    public void testGetEncryptedDataNegative(String secretAlias, String secretValue) {

        when(getSecretValueResponse.secretString()).thenReturn(secretValue);
        Whitebox.setInternalState(awsSecretRepositorySecretRetrieval, "encryptionEnabled", true);

        String retrievedSecret = awsSecretRepositorySecretRetrieval.getEncryptedData(secretAlias);

        /*
        The exception is thrown in a private method and is caught by the public method and an error is logged.
        Therefore, we cannot assert that the exception has been thrown and due to that, the assertion is done to
        check whether the error has been logged with the required exception.
        */
        verify(logger).error(anyString(), any(AWSVaultException.class));
        Assert.assertEquals(retrievedSecret, "");
        Mockito.reset(logger);
        when(logger.isDebugEnabled()).thenReturn(true);
    }

    @DataProvider(name = "initDataProvider")
    Object[][] getInitData() {

        return new Object[][]{
                {"true", true},
                {"false", false},
                {null, false}
        };
    }

    @DataProvider(name = "secretDataProviderPositive")
    Object[][] getSecretDataPositive() {

        return new Object[][]{
                {"name1#123123324345", "secret1"},
                {"name2", "secret2"},
                {"name3#", "secret3"},
        };
    }

    @DataProvider(name = "secretDataProviderNegative")
    Object[][] getSecretDataNegative() {

        return new Object[][]{
                {"", "secret1"},
                {"#version", "secret2"},
                {"test#abc#name2", "secret42"}
        };
    }
}
