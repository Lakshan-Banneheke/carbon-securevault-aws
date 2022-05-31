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
import org.wso2.carbon.securevault.aws.exception.AWSVaultException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProviderChain;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.auth.credentials.InstanceProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.WebIdentityTokenFileCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.AWS_REGION;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.COMMA;
import static org.wso2.carbon.securevault.aws.common.AWSVaultConstants.CREDENTIAL_PROVIDERS;

/**
 * Provides an instance of the secrets client that connects to the AWS Secrets Manager.
 */
public class AWSSecretManagerClient {

    private static final Log log = LogFactory.getLog(AWSSecretManagerClient.class);

    private static SecretsManagerClient secretsClient;

    private AWSSecretManagerClient() {

    }

    /**
     * Get the instance of the AWS SecretsManagerClient.
     * If one has not yet been created, the method will create a client and return it.
     *
     * @param properties Configuration properties.
     * @return AWS Secrets Manager Client instance.
     */
    public static synchronized SecretsManagerClient getInstance(Properties properties) {

        if (secretsClient == null) {
            Region region = getAWSRegion(properties);
            AwsCredentialsProvider credentialsProvider = getCredentialProviderChain(properties);
            SdkHttpClient crtClient =  ApacheHttpClient.create();

            secretsClient = SecretsManagerClient.builder()
                    .region(region)
                    .credentialsProvider(credentialsProvider)
                    .httpClient(crtClient)
                    .build();
            log.info("AWS Secrets Client created.");
        }
        return secretsClient;
    }

    /**
     * Method to get the AWS Region from the properties file.
     *
     * @param properties Configuration properties.
     * @return The AWS Region.
     * @throws AWSVaultException If the AWS Region is not set in the properties file or if it is invalid.
     */
    private static Region getAWSRegion(Properties properties) throws AWSVaultException {

        String regionString = AWSVaultUtils.getProperty(properties, AWS_REGION);
        Region region = Region.of(regionString);
        if (!Region.regions().contains(region)) {
            throw new AWSVaultException("AWS Region specified is invalid. Cannot build AWS Secrets Client!");
        }
        return region;
    }

    /**
     * Method to get the AWS Credential Provider Chain based on the configuration in the config file.
     * It will create a custom AWS Credential Provider Chain with all the provider types specified comma separated.
     *
     * @param properties Configuration properties.
     * @return AwsCredentialsProvider.
     * @throws AWSVaultException If the provider types are not specified or invalid.
     */
    private static AwsCredentialsProvider getCredentialProviderChain(Properties properties) throws AWSVaultException {

        List<AwsCredentialsProvider> awsCredentialsProviders = new ArrayList<>();
        String credentialProvidersString = AWSVaultUtils.getProperty(properties, CREDENTIAL_PROVIDERS, "default");
        String[] credentialProviderTypes = credentialProvidersString.split(COMMA);

        addCredentialProviders(awsCredentialsProviders, credentialProviderTypes);

        if (log.isDebugEnabled()) {
            log.debug("Custom credential provider chain has been created for AWS authentication.");
        }
        return AwsCredentialsProviderChain.builder().credentialsProviders(awsCredentialsProviders).build();
    }

    /**
     * Util method to add create and add the AWS credential providers specified in the config file to the list.
     * @param awsCredentialsProviders List of AWS credential providers.
     * @param credentialProviderTypes List of AWS credential provider types specified in the config file.
     */
    private static void addCredentialProviders(List<AwsCredentialsProvider> awsCredentialsProviders,
                                               String[] credentialProviderTypes) {
        //If new credential provider types are needed to be added, add a new mapping in the switch statement.
        for (String credentialType : credentialProviderTypes) {
            switch (credentialType) {
                case "env":
                    awsCredentialsProviders.add(EnvironmentVariableCredentialsProvider.create());
                    if (log.isDebugEnabled()) {
                        log.debug("Environment credential provider added to custom authentication chain.");
                    }
                    break;
                case "ec2":
                    awsCredentialsProviders.add(InstanceProfileCredentialsProvider.create());
                    if (log.isDebugEnabled()) {
                        log.debug("Instance Profile credential provider added to custom authentication chain.");
                    }
                    break;
                case "ecs":
                    awsCredentialsProviders.add(ContainerCredentialsProvider.builder().build());
                    if (log.isDebugEnabled()) {
                        log.debug("Container credential provider added to custom authentication chain.");
                    }
                    break;
                case "cli":
                case "profile":
                    awsCredentialsProviders.add(ProfileCredentialsProvider.create());
                    if (log.isDebugEnabled()) {
                        log.debug("Profile credential provider (Authentication through AWS CLI) added to " +
                                "custom authentication chain.");
                    }
                    break;
                case "webIdentity":
                case "k8sServiceAccount":
                    awsCredentialsProviders.add(WebIdentityTokenFileCredentialsProvider.create());
                    if (log.isDebugEnabled()) {
                        log.debug("Web Identity Token File credential provider (Authentication through " +
                                "Kubernetes Service Account) added to custom authentication chain.");
                    }
                    break;
                case "default":
                    awsCredentialsProviders.add(DefaultCredentialsProvider.create());
                    if (log.isDebugEnabled()) {
                        log.debug("Default credential provider added to custom authentication chain.");
                    }
                    break;
                default:
                    log.warn("Credential provider type specified is invalid. Using Default credential provider chain.");
                    awsCredentialsProviders.add(DefaultCredentialsProvider.create());
                    break;
            }
        }
    }
}
