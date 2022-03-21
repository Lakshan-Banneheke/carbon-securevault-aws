# AWS Secrets Manager based extension for WSO2 Carbon Secure Vault

#### This extension is to facilitate the integration of AWS Secrets Manager as a Secure Vault for secret storage within the WSO2 Identity Server.

***Note: This extension is compatible with WSO2 Identity Server 5.12.0 onwards.***

## Setting up

### Step 1: Building and Integrating the Extension into the Identity Server

1. Clone this project onto your computer or download it as a zip.
2. Build the OSGi bundle for the extension by running `mvn clean install`.
3. Copy the `org.wso2.carbon.securevault.aws-1.0.jar` file from the target directory within the project and insert into
   the `<IS_HOME>/repository/components/dropins/` directory in the WSO2 Identity Server.

### Step 2: Configuring the Carbon Server to use the AWS extension for secrets management

Set the following configurations in the `secret-conf.properties` file located
at `<IS_HOME>/repository/conf/security/secret-conf.properties`. Use either of the two methods given below.

#### Novel method for using multiple vault secret repositories

```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.alias=wso2carbon
keystore.identity.store.password=identity.store.password
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler

secVault.enabled=true
secretProviders=vault
secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
secretProviders.vault.repositories=aws,<Other repositories, if any>
secretProviders.vault.repositories.aws=org.wso2.carbon.securevault.aws.secret.repository.AWSSecretRepository
secretProviders.vault.repositories.aws.properties.awsregion=<AWS_Region>
secretProviders.vault.repositories.aws.properties.credentialProviders=<Credential_Provider_Type>
secretRepositories.vault.properties.encryption=false

```

#### Legacy method for using a single vault secret repository

```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.alias=wso2carbon
keystore.identity.store.password=identity.store.password
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.DefaultSecretCallbackHandler
carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler

secVault.enabled=true
secretRepositories=vault
secretRepositories.vault.provider=org.wso2.carbon.securevault.aws.secret.repository.AWSSecretRepositoryProvider
secretRepositories.vault.properties.awsregion=<AWS_Region>
secretRepositories.vault.properties.credentialProviders=<Credential_Provider_Type>
secretRepositories.vault.properties.encryption=<ENCRYPTION_ENABLED>
```

Set appropriate values for `<AWS_REGION>`, `<Credential_Provider_Type>`, `<ENCRYPTION_ENABLED>`

`<AWS_REGION>` - The region where the AWS Secrets Manager is deployed.

Eg: `secretRepositories.vault.properties.awsregion=us-east-2`

`<Credential_Provider_Type>` - Specify the credential provider type to be used to authenticate the user into AWS. Valid
values are `env`, `ecs`, `ec2`, `cli`, `profile`, `webIdentity`, `k8sServiceAccount`, `default`. These values can be
added singularly or comma separate to form an authentication chain in the specified order. This is further explained in
Step 3.

`<ENCRYPTION_ENABLED>` - Specify either true or false. If set to true, the secrets stored in the AWS Secrets Manager (
except the root password) has to be encrypted beforehand using the cipher tool. Please not that if you are using the
novel method for configuration, this property has to be set to false. Encryption is only supported for legacy method.

### Step 3: Setting up AWS Credentials for authentication

The credential provider type for authentication into AWS can be set by the `<Credential_Provider_Type>` as mentioned
above.

1. `env` - It uses
   the [EnvironmentVariableCredentialsProvider](https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/auth/credentials/EnvironmentVariableCredentialsProvider.html)
   class to load credentials from the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY system environment variables.
2. `ecs` - It uses
   the [ContainerCredentialsProvider](https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/auth/credentials/ContainerCredentialsProvider.html)
   class to load credentials from a local metadata service using the AWS_CONTAINER_CREDENTIALS_RELATIVE_URI system
   environment variable.
3. `ec2` - It uses
   the [InstanceProfileCredentialsProvider](https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/auth/credentials/InstanceProfileCredentialsProvider.html)
   class to load credentials from the Amazon EC2 metadata service.
4. `cli` or `profile` - Both of these are the same and uses
   the [ProfileCredentialsProvider](https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/auth/credentials/ProfileCredentialsProvider.html)
   to load credentials from credential profile file at the default location (~/.aws/credentials) with default profile
   name shared by all AWS SDKs and the AWS CLI. If the user is logged into AWS using the AWS CLI, this provider type can
   be used.
5. `webIdentity` or `k8sServiceAccount` - Both of these are the same and uses
   the [WebIdentityTokenFileCredentialsProvider](https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/auth/credentials/WebIdentityTokenFileCredentialsProvider.html)
   to load credentials from a web identity token file. This provider type is used when using a Kubernetes service
   account to authenticate into Secrets Manager when deployed on an AWS EKS cluster. For more info
    - [IAM roles for service accounts on EKS](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
      .
6. `default` - It uses
   the [DefaultCredentialsProvider](https://sdk.amazonaws.com/java/api/latest/software/amazon/awssdk/auth/credentials/DefaultCredentialsProvider.html)
   class to build the default authentication chain.

More than one type can also be used by specifying multiple types comma separated. The extension will build a custom
authentication chain in the order of the specified types.

Examples:

Single credential provider type: `secretRepositories.vault.properties.credentialProviders=env`

Multiple credential provider types: `secretRepositories.vault.properties.credentialProviders=env,ecs,ec2`

The appropriate environment variables based on the selected credential provider type must be set.

Eg: If `env` is selected, the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` system environment variables must be set.

### Step 4: Configuring debug logs.

Add the following lines to the `<IS_HOME>/repository/conf/log4j2.properties` file

```
logger.org-wso2-carbon-securevault-aws.name=org.wso2.carbon.securevault.aws
logger.org-wso2-carbon-securevault-aws.level=DEBUG
logger.org-wso2-carbon-securevault-aws.additivity=false
logger.org-wso2-carbon-securevault-aws.appenderRef.CARBON_CONSOLE.ref = CARBON_CONSOLE
```

Then append `org-wso2-carbon-securevault-aws` to the `loggers` list in the same file as follows.

   ```
   loggers = AUDIT_LOG, trace-messages, ... ,org-wso2-carbon-securevault-aws
   ```

## Using the extension for secret storage and retrieval.

## Referencing Deployment Secrets

### Step 1: Replace plain-text passwords with aliases.

Open the `deployment.toml` file (`<IS_HOME>/repository/conf/deployment.toml`) and replace the plain-text passwords with
an alias in the below mentioned way.

#### When using a single secret repository

```
[super_admin]
username = "admin"
password = "$secret{admin-password}"
create_admin_account = true

[keystore.primary]
file_name = "wso2carbon.jks"
password = "$secret{keystore-password}"

[truststore]
file_name="client-truststore.jks"
password="$secret{truststore-password}"
type="JKS"
```

#### When using multiple secret repositories

The secret should be referenced as;

```
"$secret{vault:aws:admin-password}"
```

The alias (eg: `admin-password`) is the name of the secret that is stored in the AWS Secrets Manager.

#### Retrieving versions of secrets

Using the alias without specifying a version as shown above will retrieve the latest version of the secret.

In order to retrieve a specific version of a secret, the `versionID` has to be mentioned after the alias separated by
a `#` as shown below.

```
[keystore.primary]
file_name = "wso2carbon.jks"
password = "$secret{keystore-password#9d21179b-cd37-4174-a65a-7d1cea075dcd}"
```

### Step 2: Enable runtime secrets.

Add the following lines to the `deployment.toml` file.

```
[runtime_secrets]
enable = "true"
```

Now the secrets stored in the connected AWS Secrets Manager with the specified secret names and versions will be
retrieved and used within the server.

## Setting up Carbon Secure Vault Root Password retrieval

The keystore and private key password must be set when using the server.

***Note: If the server is not specifically configured to retrieve these root passwords from the AWS Secrets Manager by
following the below steps, it will use the default procedure to retrieve these passwords by either reading from
the `password-tmp` or `password-persist` in the `<IS_HOME>` directory or by prompting for manual insertion in the
command line.***

### Step 1: Configuring the Carbon Server to use AWS to retrieve the root passwords.

Set the following configurations in the `secret-conf.properties` file located
at `<IS_HOME>/repository/conf/security/secret-conf.properties`.

#### Novel method for using multiple vault secret repositories

```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.alias=wso2carbon
keystore.identity.store.password=identity.store.password
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.aws.secret.handler.AWSSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.aws.secret.handler.AWSSecretCallbackHandler
carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
keystore.identity.store.alias=<identity-keystore-password-alias>
keystore.identity.key.alias=<private-key-alias>

secVault.enabled=true
secretProviders=vault
secretProviders.vault.provider=org.wso2.securevault.secret.repository.VaultSecretRepositoryProvider
secretProviders.vault.repositories=aws,<Other repositories if any>
secretProviders.vault.repositories.aws=org.wso2.carbon.securevault.aws.secret.repository.AWSSecretRepository
secretProviders.vault.repositories.aws.properties.awsregion=<AWS_Region>
secretProviders.vault.repositories.aws.properties.credentialProviders=<Credential_Provider_Type>
secretRepositories.vault.properties.encryption=false
```

#### Legacy method for using a single vault secret repository

```
keystore.identity.location=repository/resources/security/wso2carbon.jks
keystore.identity.type=JKS
keystore.identity.alias=wso2carbon
keystore.identity.store.password=identity.store.password
keystore.identity.store.secretProvider=org.wso2.carbon.securevault.aws.secret.handler.AWSSecretCallbackHandler
keystore.identity.key.password=identity.key.password
keystore.identity.key.secretProvider=org.wso2.carbon.securevault.aws.secret.handler.AWSSecretCallbackHandler
carbon.secretProvider=org.wso2.securevault.secret.handler.SecretManagerSecretCallbackHandler
keystore.identity.store.alias=<identity-keystore-password-alias>
keystore.identity.key.alias=<private-key-alias>

secVault.enabled=true
secretRepositories=vault
secretRepositories.vault.provider=org.wso2.carbon.securevault.aws.secret.repository.AWSSecretRepositoryProvider
secretRepositories.vault.properties.awsregion=<AWS_Region>
secretRepositories.vault.properties.credentialProviders=<Credential_Provider_Type>
secretRepositories.vault.properties.encryption=<ENCRYPTION_ENABLED>
```

`<AWS_REGION>`, `<Credential_Provider_Type>` and `<ENCRYPTION_ENABLED>` are same as in Setting up - Step 2.

`<identity-keystore-password-alias>` - Secret Name used to store the identity keystore password.

`<private-key-alias>` - Secret Name used to store the private key.

The above secrets use the same versioning mechanism as deployment secrets mentioned in the previous step.

### Step 2: Store the secrets in AWS Secrets Manager.

Log in to AWS Secrets Manager and create secrets using the aliases used above to store the required passwords.

Note: If encryption is enabled, the secrets (except the root password) have to be encrypted beforehand using the cipher
tool and the encrypted value should be stored.

[A guide to deploying the IS with this extension on an AWS EKS cluster.](https://docs.google.com/document/d/1-SokAGTqhyABNKLxGOrZrQnhSgcjdeHvumlt9BDyAv8/edit?usp=sharing)

##### Now you are all set to use the AWS Secrets Manager based extension for WSO2 Carbon Secure Vault 😄
