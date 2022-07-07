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

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.securevault.aws.exception.AWSVaultRuntimeException;
import org.wso2.carbon.securevault.aws.secret.repository.AWSSecretRepository;
import org.wso2.securevault.secret.SingleSecretCallback;

import java.io.FileInputStream;
import java.util.Properties;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.whenNew;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.IDENTITY_KEY_PASSWORD_ALIAS;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.IDENTITY_STORE_PASSWORD_ALIAS;

/**
 * Unit test class for AWSSecretCallbackHandler.
 */
@PrepareForTest({AWSSecretCallbackHandler.class})
public class AWSSecretCallbackHandlerTest extends PowerMockTestCase {

    public static final String IDENTITY_KEYSTORE_PASSWORD_ALIAS_VALUE = "identity-keystore-password";
    public static final String SAMPLE_KEYSTORE_PASSWORD = "sample-password";
    public static final String PRIVATE_KEY_PASSWORD_ALIAS_VALUE = "private-key";
    public static final String SAMPLE_PRIVATE_KEY_PASSWORD = "sample-password";
    private AWSSecretCallbackHandler awsSecretCallbackHandler;
    private SingleSecretCallback singleSecretCallback;
    private AWSSecretRepository awsSecretRepository;
    private Properties properties;

    @BeforeMethod
    public void setUpBeforeMethod() throws Exception {

        awsSecretCallbackHandler = new AWSSecretCallbackHandler();
        System.setProperty("key.password", "false");

        singleSecretCallback = mock(SingleSecretCallback.class);
        Whitebox.setInternalState(AWSSecretCallbackHandler.class, "keyStorePassword", "");
        Whitebox.setInternalState(AWSSecretCallbackHandler.class, "privateKeyPassword", "");

        awsSecretRepository = mock(AWSSecretRepository.class);
        whenNew(AWSSecretRepository.class).withNoArguments().thenReturn(awsSecretRepository);
        when(awsSecretRepository.getSecret(IDENTITY_KEYSTORE_PASSWORD_ALIAS_VALUE))
                .thenReturn(SAMPLE_KEYSTORE_PASSWORD);

        properties = mock(Properties.class);
        whenNew(Properties.class).withNoArguments().thenReturn(properties);
        when(properties.getProperty(IDENTITY_STORE_PASSWORD_ALIAS)).thenReturn(IDENTITY_KEYSTORE_PASSWORD_ALIAS_VALUE);
        when(properties.getProperty(IDENTITY_KEY_PASSWORD_ALIAS)).thenReturn(PRIVATE_KEY_PASSWORD_ALIAS_VALUE);

        whenNew(FileInputStream.class).withArguments(anyString()).thenReturn(mock(FileInputStream.class));
    }

    @Test(description = "Positive case for handleSingleSecretCallback() for private key password when both are equal.")
    public void testHandleSingleSecretCallbackPrivateKeyEqual() {

        when(singleSecretCallback.getId()).thenReturn("identity.key.password");
        awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback);

        Assert.assertEquals(Whitebox.getInternalState(AWSSecretCallbackHandler.class, "privateKeyPassword"),
                SAMPLE_PRIVATE_KEY_PASSWORD);
        verify(singleSecretCallback).setSecret(SAMPLE_PRIVATE_KEY_PASSWORD);
    }

    @Test(description = "Positive case for handleSingleSecretCallback() for key store password when both are equal.")
    public void testHandleSingleSecretCallbackKeyStorePasswordEqual() {

        when(singleSecretCallback.getId()).thenReturn("identity.store.password");
        awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback);

        Assert.assertEquals(Whitebox.getInternalState(AWSSecretCallbackHandler.class, "keyStorePassword"),
                SAMPLE_KEYSTORE_PASSWORD);
        verify(singleSecretCallback).setSecret(SAMPLE_KEYSTORE_PASSWORD);
    }

    @Test(description = "Positive case for handleSingleSecretCallback() for private key password " +
            "when they are different.")
    public void testHandleSingleSecretCallbackPrivateKeyDifferent() {

        System.setProperty("key.password", "true");
        String samplePrivateKeyPassword = "sample-password2";
        when(singleSecretCallback.getId()).thenReturn("identity.key.password");
        when(awsSecretRepository.getSecret(PRIVATE_KEY_PASSWORD_ALIAS_VALUE)).thenReturn(samplePrivateKeyPassword);
        awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback);

        Assert.assertEquals(
                Whitebox.getInternalState(AWSSecretCallbackHandler.class, "privateKeyPassword"),
                samplePrivateKeyPassword
        );
        Assert.assertNotEquals(
                Whitebox.getInternalState(AWSSecretCallbackHandler.class, "keyStorePassword"),
                samplePrivateKeyPassword
        );
        verify(singleSecretCallback).setSecret(samplePrivateKeyPassword);
    }

    @Test(description = "Positive case for handleSingleSecretCallback() for private key password when it is set.")
    public void testHandleSingleSecretCallbackPrivateKeySet() {

        Whitebox.setInternalState(AWSSecretCallbackHandler.class, "privateKeyPassword",
                SAMPLE_PRIVATE_KEY_PASSWORD);
        when(singleSecretCallback.getId()).thenReturn("identity.key.password");
        awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback);

        Assert.assertEquals(Whitebox.getInternalState(AWSSecretCallbackHandler.class, "privateKeyPassword"),
                SAMPLE_PRIVATE_KEY_PASSWORD);
        verify(singleSecretCallback).setSecret(SAMPLE_PRIVATE_KEY_PASSWORD);
    }

    @Test(description = "Positive case for handleSingleSecretCallback() for key store password when it is set.")
    public void testHandleSingleSecretCallbackKeyStorePasswordSet() {

        Whitebox.setInternalState(AWSSecretCallbackHandler.class, "keyStorePassword",
                SAMPLE_PRIVATE_KEY_PASSWORD);
        when(singleSecretCallback.getId()).thenReturn("identity.store.password");
        awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback);

        Assert.assertEquals(Whitebox.getInternalState(AWSSecretCallbackHandler.class, "keyStorePassword"),
                SAMPLE_KEYSTORE_PASSWORD);
        verify(singleSecretCallback).setSecret(SAMPLE_KEYSTORE_PASSWORD);
    }

    @Test(description = "Positive case for handleSingleSecretCallback() when both are set.")
    public void testHandleSingleSecretCallbackBothSet() {

        Whitebox.setInternalState(AWSSecretCallbackHandler.class, "privateKeyPassword",
                SAMPLE_PRIVATE_KEY_PASSWORD);
        Whitebox.setInternalState(AWSSecretCallbackHandler.class, "keyStorePassword",
                SAMPLE_PRIVATE_KEY_PASSWORD);
        when(singleSecretCallback.getId()).thenReturn("identity.key.password");
        awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback);

        Assert.assertEquals(Whitebox.getInternalState(AWSSecretCallbackHandler.class, "privateKeyPassword"),
                SAMPLE_PRIVATE_KEY_PASSWORD);
        Assert.assertEquals(Whitebox.getInternalState(AWSSecretCallbackHandler.class, "keyStorePassword"),
                SAMPLE_KEYSTORE_PASSWORD);
    }

    @Test(description = "Negative case for handleSingleSecretCallback() where keystore.identity.store.alias is empty.")
    public void testHandleSingleSecretCallbackEmptyAliasKeyStore() {

        when(properties.getProperty(IDENTITY_STORE_PASSWORD_ALIAS)).thenReturn(null);
        when(singleSecretCallback.getId()).thenReturn("identity.store.password");
        Throwable exception = assertThrows(
                AWSVaultRuntimeException.class,
                () -> awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback)
        );

        Assert.assertEquals(exception.getMessage(), IDENTITY_STORE_PASSWORD_ALIAS + " property has not been set.");
    }

    @Test(description = "Negative case for handleSingleSecretCallback() where keyStorePassword is empty.")
    public void testHandleSingleSecretCallbackEmptySecretKeyStore() {

        when(awsSecretRepository.getSecret(IDENTITY_KEYSTORE_PASSWORD_ALIAS_VALUE)).thenReturn(null);
        when(singleSecretCallback.getId()).thenReturn("identity.store.password");
        Throwable exception = assertThrows(
                AWSVaultRuntimeException.class,
                () -> awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback)
        );

        Assert.assertEquals(exception.getMessage(), "Error in retrieving " + IDENTITY_STORE_PASSWORD_ALIAS +
                " property.");
    }

    @Test(description = "Negative for handleSingleSecretCallback() where keystore.identity.key.alias is empty " +
            "and the passwords are different.")
    public void testHandleSingleSecretCallbackEmptyAliasPrivateKey() {

        System.setProperty("key.password", "true");
        when(properties.getProperty(IDENTITY_KEY_PASSWORD_ALIAS)).thenReturn(null);
        when(singleSecretCallback.getId()).thenReturn("identity.key.password");
        Throwable exception = assertThrows(
                AWSVaultRuntimeException.class,
                () -> awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback)
        );

        Assert.assertEquals(exception.getMessage(), IDENTITY_KEY_PASSWORD_ALIAS + " property has not been set.");
    }

    @Test(description = "Negative case for handleSingleSecretCallback() where privateKeyPassword secret is empty " +
            "and the passwords are different.")
    public void testHandleSingleSecretCallbackEmptySecretPrivateKey() {

        System.setProperty("key.password", "true");
        when(singleSecretCallback.getId()).thenReturn("identity.key.password");
        Throwable exception = assertThrows(
                AWSVaultRuntimeException.class,
                () -> awsSecretCallbackHandler.handleSingleSecretCallback(singleSecretCallback)
        );

        Assert.assertEquals(
                exception.getMessage(),
                "Error in retrieving " + IDENTITY_KEY_PASSWORD_ALIAS + " property."
        );
    }
}
