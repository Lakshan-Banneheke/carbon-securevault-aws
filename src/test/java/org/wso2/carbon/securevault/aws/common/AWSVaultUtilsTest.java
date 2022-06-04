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
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.util.Properties;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;

/**
 * Unit test class for AWSVaultUtils.
 */
@PrepareForTest({LogFactory.class})
public class AWSVaultUtilsTest extends PowerMockTestCase {

    public static final String TEST_PROPERTY = "testProperty";
    private Log logger;

    @BeforeClass
    public void setUp() {

        mockStatic(LogFactory.class);
        logger = mock(Log.class);
        when(LogFactory.getLog(AWSVaultUtils.class)).thenReturn(logger);
        when(logger.isDebugEnabled()).thenReturn(true);
    }

    @BeforeMethod
    public void beforeMethod() {

        Whitebox.setInternalState(AWSVaultUtils.class, "propertiesPrefix", "");
    }

    @Test(description = "Positive test case for getProperty() if configs are in legacy method.")
    public void testGetPropertyLegacyConfig() {

        Properties configProperties = getLegacyConfigProperties();
        String propertyValueFromMethod = AWSVaultUtils.getProperty(configProperties, "test");
        Assert.assertEquals(propertyValueFromMethod, TEST_PROPERTY);
    }

    @Test(description = "Positive test case for getProperty() if configs are in novel method.")
    public void testGetPropertyNovelConfig() {

        Properties configProperties = getNovelConfigProperties();
        String propertyValueFromMethod = AWSVaultUtils.getProperty(configProperties, "test");
        Assert.assertEquals(propertyValueFromMethod, TEST_PROPERTY);
    }

    @Test(description = "Negative test case for getProperty() if property not specified.")
    public void testGetPropertyUnspecified() {

        Properties configProperties = getNovelConfigProperties();
        String propertyValueFromMethod = AWSVaultUtils.getProperty(configProperties, "test123");
        Assert.assertNull(propertyValueFromMethod);
        verify(logger).warn(anyString());
    }

    @Test(description = "Negative test case for getProperty() if configs null.")
    public void testGetPropertyNullProperties() {

        assertThrows(
                IllegalArgumentException.class,
                () -> AWSVaultUtils.getProperty(null, "test")
        );
    }

    private Properties getLegacyConfigProperties() {

        Properties configProperties = new Properties();
        configProperties.setProperty("secretRepositories", "vault");
        configProperties.setProperty("secretRepositories.vault.properties.test", TEST_PROPERTY);
        return configProperties;
    }

    private Properties getNovelConfigProperties() {

        Properties configProperties = new Properties();

        configProperties.setProperty("secretProviders", "vault");
        configProperties.setProperty("secretProviders.vault.repositories.aws.properties.test", TEST_PROPERTY);

        return configProperties;
    }

}