# akeyless-proxy-api
RESTFull API for interacting with AKEYLESS Proxy Vault

This Python package is automatically generated by the [Swagger Codegen](https://github.com/swagger-api/swagger-codegen) project:

- API version: 0.1.0
- Package version: 0.1.0
- Build package: io.swagger.codegen.languages.PythonClientCodegen
For more information, please visit [https://www.akeyless.io](https://www.akeyless.io)

## Requirements.

Python 2.7 and 3.4+

## Installation & Usage
### pip install

```sh
pip install akeyless-proxy-api
```
(you may need to run `pip` with root permission: `sudo pip install akeyless-proxy-api`)

Then import the package:
```python
import akeyless_proxy_api 
```

### Setuptools

Install via [Setuptools](http://pypi.python.org/pypi/setuptools).

```sh
python setup.py install --user
```
(or `sudo python setup.py install` to install the package for all users)

Then import the package:
```python
import akeyless_proxy_api
```

## Getting Started

Please follow the [installation procedure](#installation--usage) and then run the following:

```python
from __future__ import print_function
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from akeyless_proxy_api.configuration import Configuration
from pprint import pprint


api_conf = Configuration()
api_conf.host = "127.0.0.1:8080" # str | The proxy host address.

# create an instance of the Proxy API class
api_client = akeyless_proxy_api.ApiClient(api_conf)
api_instance =  akeyless_proxy_api.DefaultApi(api_client)

access_id = 'access_id_example' # str | Access ID
access_type = 'access_type_example' # str | Access Type (api_key/okta_saml/ldap) (optional)
access_key = 'access_key_example' # str | Access key (relevant only for access-type=api_key) (optional)

try:
    # Authenticate to the service and returns an access token
    auth_response = api_instance.auth(access_id, access_type=access_type, access_key=access_key)
    token = auth_response.token

    # Create new static secret
    secret_name = 'name_example' # str | Secret name
    secret_value = 'value_example' # str | The secret value
    secret_metadata = 'metadata_example' # str | Metadata about the secret (optional)
    create_response =  api_instance.create_secret(secret_name, secret_value, token, metadata=secret_metadata)
    pprint(create_response.response)

    # Get static secret value
    secret_val_res = api_instance.get_secret_value(secret_name, token)
    pprint(secret_val_res.response)

    # Get static secret details
    desc_response = api_instance.describe_item(secret_name, token)
    pprint(desc_response)

    # Update static secret value
    new_secret_value = "this is a new secret"
    api_instance.update_secret_val(secret_name, new_secret_value, token)
    secret_val_res = api_instance.get_secret_value(secret_name, token)
    pprint(secret_val_res.response)


except ApiException as e:
    print("Exception when calling proxy api: %s\n" % e)

```

The following example show how to fetch multiple secrets values with async requests
```
from __future__ import print_function
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from akeyless_proxy_api.configuration import Configuration
from akeyless_proxy_api.api_client import ApiClient
from pprint import pprint

# create an instance of the Proxy API class
api_conf = Configuration()
api_conf.host = "127.0.0.1:8080" # str | The proxy host address.
api_client = akeyless_proxy_api.ApiClient(api_conf)
api_instance =  akeyless_proxy_api.DefaultApi(api_client)
access_id = 'access_id_example' # str | Access ID
access_type = 'access_type_example' # str | Access Type (api_key/okta_saml/ldap) (optional)
access_key = 'access_key_example' # str | Access key (relevant only for access-type=api_key) (optional)

try:
    # Authenticate to the service and returns an access token
    auth_response = api_instance.auth(access_id, access_type=access_type, access_key=access_key)
    token = auth_response.token

    secrets_names = ["mySecret1", "mySecret2", "mySecret3", "mySecret4", "mySecret5"]

    threads = []
    for name in secrets_names:
        threads.append(api_instance.get_secret_value(name, token, async_req=True))

    for t in threads:
        secret_val_res = t.get()
        pprint(secret_val_res.response)


except ApiException as e:
    print("Exception when calling proxy api: %s\n" % e)
```

## Documentation for API Endpoints

All URIs are relative to *http://127.0.0.1:8080*

Class | Method | HTTP request | Description
------------ | ------------- | ------------- | -------------
*DefaultApi* | [**auth**](docs/DefaultApi.md#auth) | **POST** /auth | Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication
*DefaultApi* | [**create_secret**](docs/DefaultApi.md#create_secret) | **POST** /create-secret | Creates a new secret item
*DefaultApi* | [**get_secret_value**](docs/DefaultApi.md#get_secret_value) | **POST** /get-secret-value | Get static secret value
*DefaultApi* | [**update_secret_val**](docs/DefaultApi.md#update_secret_val) | **POST** /update-secret-val | Update static secret value
*DefaultApi* | [**describe_item**](docs/DefaultApi.md#describe_item) | **POST** /describe-item | Returns the item details
*DefaultApi* | [**list_items**](docs/DefaultApi.md#list_items) | **POST** /list-items | Returns a list of all accessible items
*DefaultApi* | [**update_item**](docs/DefaultApi.md#update_item) | **POST** /update-item | Update item name and metadata
*DefaultApi* | [**create_key**](docs/DefaultApi.md#create_key) | **POST** /create-key | Creates a new key
*DefaultApi* | [**encrypt**](docs/DefaultApi.md#encrypt) | **POST** /encrypt | Encrypts plaintext into ciphertext by using an AES key
*DefaultApi* | [**create_auth_method**](docs/DefaultApi.md#create_auth_method) | **POST** /create-auth-method | Create a new Auth Method in the account
*DefaultApi* | [**create_auth_method_azure_ad**](docs/DefaultApi.md#create_auth_method_azure_ad) | **POST** /create-auth-method-azure-ad | Create a new Auth Method that will be able to authentication using Azure Active Directory credentials
*DefaultApi* | [**create_auth_method_ldap**](docs/DefaultApi.md#create_auth_method_ldap) | **POST** /create-auth-method-ldap | Create a new Auth Method that will be able to authentication using LDAP
*DefaultApi* | [**create_auth_method_oauth2**](docs/DefaultApi.md#create_auth_method_oauth2) | **POST** /create-auth-method-oauth2 | Create a new Auth Method that will be able to authentication using OpenId/OAuth2
*DefaultApi* | [**create_auth_method_saml**](docs/DefaultApi.md#create_auth_method_saml) | **POST** /create-auth-method-saml | Create a new Auth Method that will be able to authentication using SAML
*DefaultApi* | [**assoc_role_am**](docs/DefaultApi.md#assoc_role_am) | **POST** /assoc-role-am | Create an association between role and auth method
*DefaultApi* | [**create_dynamic_secret**](docs/DefaultApi.md#create_dynamic_secret) | **POST** /create-dynamic-secret | Creates a new dynamic secret item
*DefaultApi* | [**create_role**](docs/DefaultApi.md#create_role) | **POST** /create-role | Creates a new role
*DefaultApi* | [**create_ssh_cert_issuer**](docs/DefaultApi.md#create_ssh_cert_issuer) | **POST** /create-ssh-cert-issuer | Creates a new SSH certificate issuer
*DefaultApi* | [**decrypt**](docs/DefaultApi.md#decrypt) | **POST** /decrypt | Decrypts ciphertext into plaintext by using an AES key
*DefaultApi* | [**decrypt_pkcs1**](docs/DefaultApi.md#decrypt_pkcs1) | **POST** /decrypt-pkcs1 | Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5
*DefaultApi* | [**delete_assoc**](docs/DefaultApi.md#delete_assoc) | **POST** /delete-assoc | Delete an association between role and auth method
*DefaultApi* | [**delete_auth_method**](docs/DefaultApi.md#delete_auth_method) | **POST** /delete-auth-method | Delete the Auth Method
*DefaultApi* | [**delete_item**](docs/DefaultApi.md#delete_item) | **POST** /delete-item | Delete an item
*DefaultApi* | [**delete_role**](docs/DefaultApi.md#delete_role) | **POST** /delete-role | Delete a role
*DefaultApi* | [**delete_role_rule**](docs/DefaultApi.md#delete_role_rule) | **POST** /delete-role-rule | Delete a rule from a role
*DefaultApi* | [**encrypt_pkcs1**](docs/DefaultApi.md#encrypt_pkcs1) | **POST** /encrypt-pkcs1 | Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5
*DefaultApi* | [**get_auth_method**](docs/DefaultApi.md#get_auth_method) | **POST** /get-auth-method | Returns an information about the Auth Method
*DefaultApi* | [**get_dynamic_secret_value**](docs/DefaultApi.md#get_dynamic_secret_value) | **POST** /get-dynamic-secret-value | Get dynamic secret value
*DefaultApi* | [**get_role**](docs/DefaultApi.md#get_role) | **POST** /get-role | Get role details
*DefaultApi* | [**get_rsa_public**](docs/DefaultApi.md#get_rsa_public) | **POST** /get-rsa-public | Obtain the public key from a specific RSA private key
*DefaultApi* | [**get_ssh_certificate**](docs/DefaultApi.md#get_ssh_certificate) | **POST** /get-ssh-certificate | Generates SSH certificate
*DefaultApi* | [**list_auth_methods**](docs/DefaultApi.md#list_auth_methods) | **POST** /list-auth-methods | Returns a list of all the Auth Methods in the account
*DefaultApi* | [**list_roles**](docs/DefaultApi.md#list_roles) | **POST** /list-roles | Returns a list of all roles in the account
*DefaultApi* | [**set_role_rule**](docs/DefaultApi.md#set_role_rule) | **POST** /set-role-rule | Set a rule to a role
*DefaultApi* | [**sign_pkcs1**](docs/DefaultApi.md#sign_pkcs1) | **POST** /sign-pkcs1 | Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5
*DefaultApi* | [**update_role**](docs/DefaultApi.md#update_role) | **POST** /update-role | Update role details
*DefaultApi* | [**upload_pkcs12**](docs/DefaultApi.md#upload_pkcs12) | **POST** /upload-pkcs12 | Upload a PKCS#12 key and certificates
*DefaultApi* | [**upload_rsa**](docs/DefaultApi.md#upload_rsa) | **POST** /upload-rsa | Upload RSA key
*DefaultApi* | [**verify_pkcs1**](docs/DefaultApi.md#verify_pkcs1) | **POST** /verify-pkcs1 | Verifies an RSA PKCS#1 v1.5 signature
*DefaultApi* | [**configure**](docs/DefaultApi.md#configure) | **POST** /configure | Configure client profile.
*DefaultApi* | [**unconfigure**](docs/DefaultApi.md#unconfigure) | **POST** /unconfigure | Remove Configuration of client profile.
*DefaultApi* | [**help**](docs/DefaultApi.md#help) | **POST** /help | help text


## Documentation For Models

 - [ErrorReplyObj](docs/ErrorReplyObj.md)
 - [ReplyObj](docs/ReplyObj.md)


## Author

refael@akeyless.io

