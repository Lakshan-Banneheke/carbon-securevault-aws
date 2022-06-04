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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.securevault.aws.exception.AWSVaultRuntimeException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;

import java.util.Properties;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

/**
 * Unit test class for AWSSecretManagerClient.
 */
@PrepareForTest({LogFactory.class, AWSVaultUtils.class, ApacheHttpClient.class, SecretsManagerClient.class})
public class AWSSecretManagerClientTest extends PowerMockTestCase {

    private static final String AWS_REGION = "awsregion";
    private static final String CREDENTIAL_PROVIDERS = "credentialProviders";
    private Properties properties;
    private SecretsManagerClientBuilder secretsManagerClientBuilder;
    private SecretsManagerClient secretManagerClientObj;

    @BeforeMethod
    public void setUp() {

        properties = new Properties();

        mockStatic(LogFactory.class);
        Log logger = mock(Log.class);
        when(logger.isDebugEnabled()).thenReturn(true);
        when(LogFactory.getLog(AWSSecretManagerClient.class)).thenReturn(logger);

        mockStatic(AWSVaultUtils.class);

        mockStatic(ApacheHttpClient.class);
        when(ApacheHttpClient.create()).thenReturn(mock(SdkHttpClient.class));

        mockStatic(SecretsManagerClient.class);
        secretsManagerClientBuilder = mock(SecretsManagerClientBuilder.class);
        when(secretsManagerClientBuilder.region(any())).thenReturn(secretsManagerClientBuilder);
        when(secretsManagerClientBuilder.credentialsProvider(any())).thenReturn(secretsManagerClientBuilder);
        when(secretsManagerClientBuilder.httpClient(any())).thenReturn(secretsManagerClientBuilder);

        secretManagerClientObj = mock(SecretsManagerClient.class);
        when(secretsManagerClientBuilder.build()).thenReturn(secretManagerClientObj);

        when(SecretsManagerClient.builder()).thenReturn(secretsManagerClientBuilder);
    }

    @Test(description = "Test case for getInstance() method.")
    public void testGetInstance() {

        when(AWSVaultUtils.getProperty(properties, AWS_REGION)).thenReturn("us-east-2");
        when(AWSVaultUtils.getProperty(properties, CREDENTIAL_PROVIDERS)).thenReturn("env");
        SecretsManagerClient secretsManagerClient = AWSSecretManagerClient.getInstance(properties);
        Assert.assertSame(secretsManagerClient, secretManagerClientObj);

        SecretsManagerClient secretsManagerClient2 = AWSSecretManagerClient.getInstance(properties);
        Assert.assertSame(secretsManagerClient, secretsManagerClient2);
        verify(secretsManagerClientBuilder, times(1)).build();
    }

    @Test(description = "Positive test case for getAWSRegion() method.")
    public void testGetAWSRegionPositive() throws Exception {

        when(AWSVaultUtils.getProperty(properties, AWS_REGION)).thenReturn("us-east-2");
        Region region = Whitebox.invokeMethod(AWSSecretManagerClient.class, "getAWSRegion", properties);

        Assert.assertNotNull(region);
        Assert.assertEquals(region.getClass(), Region.class);
        Assert.assertEquals(region.toString(), "us-east-2");
    }

    @Test(description = "Negative test case for getAWSRegion() method for invalid region.")
    public void testGetAWSRegionNegativeInvalid() {

        when(AWSVaultUtils.getProperty(properties, AWS_REGION)).thenReturn("Invalid value");

        Throwable exception = assertThrows(
                AWSVaultRuntimeException.class,
                () -> Whitebox.invokeMethod(AWSSecretManagerClient.class, "getAWSRegion", properties)
        );
        Assert.assertEquals(
                exception.getMessage(), "AWS Region specified is invalid. Cannot build AWS Secrets Client!");
    }

    @Test(description = "Negative test case for getAWSRegion() method for empty region.")
    public void testGetAWSRegionNegativeEmpty() {

        when(AWSVaultUtils.getProperty(properties, AWS_REGION)).thenReturn(null);

        Throwable exception = assertThrows(
                AWSVaultRuntimeException.class,
                () -> Whitebox.invokeMethod(AWSSecretManagerClient.class, "getAWSRegion", properties)
        );
        Assert.assertEquals(
                exception.getMessage(), "AWS Region has not been specified. Cannot build AWS Secrets Client!");
    }

    @Test(dataProvider = "credentialDataProvider",
            description = "Test case for getCredentialProviderChain() method.")
    public void testGetCredentialProviderChain(String credentialProvidersProperty,
                                               String credentialProviders) throws Exception {

        when(AWSVaultUtils.getProperty(properties, CREDENTIAL_PROVIDERS)).thenReturn(credentialProvidersProperty);
        AwsCredentialsProvider awsCredentialsProvider = Whitebox.invokeMethod(AWSSecretManagerClient.class,
                "getCredentialProviderChain", properties);

        String[] credentialProvidersArray = credentialProviders.split(",");
        for (String credentialProvider : credentialProvidersArray) {
            assertThat(awsCredentialsProvider.toString(), containsString(credentialProvider));
        }
    }

    @DataProvider(name = "credentialDataProvider")
    Object[][] getCredentialData() {

        return new Object[][]{
                {"env", "EnvironmentVariableCredentialsProvider"},
                {"cli", "ProfileCredentialsProvider"},
                {"k8sServiceAccount", "WebIdentityTokenCredentialsProvider"},
                {"env,cli", "EnvironmentVariableCredentialsProvider, ProfileCredentialsProvider"},
                {"env, ec2, ecs, cli, k8sServiceAccount",
                        "EnvironmentVariableCredentialsProvider, InstanceProfileCredentialsProvider, " +
                                "ContainerCredentialsProvider, ProfileCredentialsProvider, " +
                                "WebIdentityTokenCredentialsProvider"},
                {"invalid", "DefaultCredentialsProvider"},
                {null, "DefaultCredentialsProvider"},
                {"", "DefaultCredentialsProvider"}
        };
    }
}
