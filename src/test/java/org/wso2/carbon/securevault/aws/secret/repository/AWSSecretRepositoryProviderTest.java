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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.securevault.keystore.IdentityKeyStoreWrapper;
import org.wso2.securevault.keystore.TrustKeyStoreWrapper;

import static org.mockito.Mockito.mock;

/**
 * Unit test class for AWSSecretRepositoryProvider.
 */
public class AWSSecretRepositoryProviderTest {

    private AWSSecretRepositoryProvider awsSecretRepositoryProvider;
    private IdentityKeyStoreWrapper identityKeyStoreWrapper;
    private TrustKeyStoreWrapper trustKeyStoreWrapper;

    @BeforeClass
    public void setUp() {

        awsSecretRepositoryProvider = new AWSSecretRepositoryProvider();
        identityKeyStoreWrapper = mock(IdentityKeyStoreWrapper.class);
        trustKeyStoreWrapper = mock(TrustKeyStoreWrapper.class);
    }

    @Test(description = "Test case for getSecretRepository() method.")
    public void testGetSecretRepository() {

        Assert.assertEquals(
                awsSecretRepositoryProvider.getSecretRepository(identityKeyStoreWrapper, trustKeyStoreWrapper)
                        .getClass(), AWSSecretRepository.class
        );
    }
}
