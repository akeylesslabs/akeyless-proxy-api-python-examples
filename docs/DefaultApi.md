# akeyless_proxy_api.DefaultApi

All URIs are relative to *http://127.0.0.1:8080*

Method | HTTP request | Description
------------- | ------------- | -------------
[**assoc_role_am**](DefaultApi.md#assoc_role_am) | **POST** /assoc-role-am | Create an association between role and auth method
[**auth**](DefaultApi.md#auth) | **POST** /auth | Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication
[**configure**](DefaultApi.md#configure) | **POST** /configure | Configure client profile.
[**create_auth_method**](DefaultApi.md#create_auth_method) | **POST** /create-auth-method | Create a new Auth Method in the account
[**create_auth_method_azure_ad**](DefaultApi.md#create_auth_method_azure_ad) | **POST** /create-auth-method-azure-ad | Create a new Auth Method that will be able to authentication using Azure Active Directory credentials
[**create_auth_method_ldap**](DefaultApi.md#create_auth_method_ldap) | **POST** /create-auth-method-ldap | Create a new Auth Method that will be able to authentication using LDAP
[**create_auth_method_oauth2**](DefaultApi.md#create_auth_method_oauth2) | **POST** /create-auth-method-oauth2 | Create a new Auth Method that will be able to authentication using OpenId/OAuth2
[**create_auth_method_saml**](DefaultApi.md#create_auth_method_saml) | **POST** /create-auth-method-saml | Create a new Auth Method that will be able to authentication using SAML
[**create_dynamic_secret**](DefaultApi.md#create_dynamic_secret) | **POST** /create-dynamic-secret | Creates a new dynamic secret item
[**create_key**](DefaultApi.md#create_key) | **POST** /create-key | Creates a new key
[**create_role**](DefaultApi.md#create_role) | **POST** /create-role | Creates a new role
[**create_secret**](DefaultApi.md#create_secret) | **POST** /create-secret | Creates a new secret item
[**create_ssh_cert_issuer**](DefaultApi.md#create_ssh_cert_issuer) | **POST** /create-ssh-cert-issuer | Creates a new SSH certificate issuer
[**decrypt**](DefaultApi.md#decrypt) | **POST** /decrypt | Decrypts ciphertext into plaintext by using an AES key
[**decrypt_file**](DefaultApi.md#decrypt_file) | **POST** /decrypt-file | Decrypts a file by using an AES key
[**decrypt_pkcs1**](DefaultApi.md#decrypt_pkcs1) | **POST** /decrypt-pkcs1 | Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5
[**delete_assoc**](DefaultApi.md#delete_assoc) | **POST** /delete-assoc | Delete an association between role and auth method
[**delete_auth_method**](DefaultApi.md#delete_auth_method) | **POST** /delete-auth-method | Delete the Auth Method
[**delete_item**](DefaultApi.md#delete_item) | **POST** /delete-item | Delete an item
[**delete_role**](DefaultApi.md#delete_role) | **POST** /delete-role | Delete a role
[**delete_role_rule**](DefaultApi.md#delete_role_rule) | **POST** /delete-role-rule | Delete a rule from a role
[**describe_item**](DefaultApi.md#describe_item) | **POST** /describe-item | Returns the item details
[**encrypt**](DefaultApi.md#encrypt) | **POST** /encrypt | Encrypts plaintext into ciphertext by using an AES key
[**encrypt_file**](DefaultApi.md#encrypt_file) | **POST** /encrypt-file | Encrypts a file by using an AES key
[**encrypt_pkcs1**](DefaultApi.md#encrypt_pkcs1) | **POST** /encrypt-pkcs1 | Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5
[**get_auth_method**](DefaultApi.md#get_auth_method) | **POST** /get-auth-method | Returns an information about the Auth Method
[**get_dynamic_secret_value**](DefaultApi.md#get_dynamic_secret_value) | **POST** /get-dynamic-secret-value | Get dynamic secret value
[**get_role**](DefaultApi.md#get_role) | **POST** /get-role | Get role details
[**get_rsa_public**](DefaultApi.md#get_rsa_public) | **POST** /get-rsa-public | Obtain the public key from a specific RSA private key
[**get_secret_value**](DefaultApi.md#get_secret_value) | **POST** /get-secret-value | Get static secret value
[**get_ssh_certificate**](DefaultApi.md#get_ssh_certificate) | **POST** /get-ssh-certificate | Generates SSH certificate
[**help**](DefaultApi.md#help) | **POST** /help | help text
[**list_auth_methods**](DefaultApi.md#list_auth_methods) | **POST** /list-auth-methods | Returns a list of all the Auth Methods in the account
[**list_items**](DefaultApi.md#list_items) | **POST** /list-items | Returns a list of all accessible items
[**list_roles**](DefaultApi.md#list_roles) | **POST** /list-roles | Returns a list of all roles in the account
[**set_role_rule**](DefaultApi.md#set_role_rule) | **POST** /set-role-rule | Set a rule to a role
[**sign_pkcs1**](DefaultApi.md#sign_pkcs1) | **POST** /sign-pkcs1 | Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5
[**unconfigure**](DefaultApi.md#unconfigure) | **POST** /unconfigure | Remove Configuration of client profile.
[**update_item**](DefaultApi.md#update_item) | **POST** /update-item | Update item name and metadata
[**update_role**](DefaultApi.md#update_role) | **POST** /update-role | Update role details
[**update_secret_val**](DefaultApi.md#update_secret_val) | **POST** /update-secret-val | Update static secret value
[**upload_pkcs12**](DefaultApi.md#upload_pkcs12) | **POST** /upload-pkcs12 | Upload a PKCS#12 key and certificates
[**upload_rsa**](DefaultApi.md#upload_rsa) | **POST** /upload-rsa | Upload RSA key
[**verify_pkcs1**](DefaultApi.md#verify_pkcs1) | **POST** /verify-pkcs1 | Verifies an RSA PKCS#1 v1.5 signature


# **assoc_role_am**
> ReplyObj assoc_role_am(role_name, am_name, token, sub_claims=sub_claims)

Create an association between role and auth method

Create an association between role and auth method Options:   role-name -    The role name to associate   am-name -    The auth method name to associate   sub-claims -    key/val of sub claims, ex. group=admins,developers   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
role_name = 'role_name_example' # str | The role name to associate
am_name = 'am_name_example' # str | The auth method name to associate
token = 'token_example' # str | Access token
sub_claims = 'sub_claims_example' # str | key/val of sub claims, ex. group=admins,developers (optional)

try:
    # Create an association between role and auth method
    api_response = api_instance.assoc_role_am(role_name, am_name, token, sub_claims=sub_claims)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->assoc_role_am: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **role_name** | **str**| The role name to associate | 
 **am_name** | **str**| The auth method name to associate | 
 **token** | **str**| Access token | 
 **sub_claims** | **str**| key/val of sub claims, ex. group&#x3D;admins,developers | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **auth**
> ReplyObj auth(access_id, access_type=access_type, access_key=access_key, ldap_proxy_url=ldap_proxy_url)

Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication

Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication Options:   access-id -    Access ID   access-type -    Access Type (api_key/okta_saml/ldap)   access-key -    Access key (relevant only for access-type=api_key)   ldap_proxy_url -    Address URL for LDAP proxy (relevant only for access-type=ldap)

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
access_id = 'access_id_example' # str | Access ID
access_type = 'access_type_example' # str | Access Type (api_key/okta_saml/ldap) (optional)
access_key = 'access_key_example' # str | Access key (relevant only for access-type=api_key) (optional)
ldap_proxy_url = 'ldap_proxy_url_example' # str | Address URL for LDAP proxy (relevant only for access-type=ldap) (optional)

try:
    # Authenticate to the service and returns a token to be used as a profile to execute the CLI without the need for re-authentication
    api_response = api_instance.auth(access_id, access_type=access_type, access_key=access_key, ldap_proxy_url=ldap_proxy_url)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->auth: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **access_id** | **str**| Access ID | 
 **access_type** | **str**| Access Type (api_key/okta_saml/ldap) | [optional] 
 **access_key** | **str**| Access key (relevant only for access-type&#x3D;api_key) | [optional] 
 **ldap_proxy_url** | **str**| Address URL for LDAP proxy (relevant only for access-type&#x3D;ldap) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **configure**
> ReplyObj configure(access_id, access_key=access_key, access_type=access_type, ldap_proxy_url=ldap_proxy_url, azure_ad_object_id=azure_ad_object_id)

Configure client profile.

Configure client profile. Options:   access-id -    Access ID   access-key -    Access Key   access-type -    Access Type (api_key/azure_ad/okta_saml/ldap)   ldap_proxy_url -    Address URL for ldap proxy (relevant only for access-type=ldap)   azure_ad_object_id -    Azure Active Directory ObjectId (relevant only for access-type=azure_ad)

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
access_id = 'access_id_example' # str | Access ID
access_key = 'access_key_example' # str | Access Key (optional)
access_type = 'access_type_example' # str | Access Type (api_key/azure_ad/okta_saml/ldap) (optional)
ldap_proxy_url = 'ldap_proxy_url_example' # str | Address URL for ldap proxy (relevant only for access-type=ldap) (optional)
azure_ad_object_id = 'azure_ad_object_id_example' # str | Azure Active Directory ObjectId (relevant only for access-type=azure_ad) (optional)

try:
    # Configure client profile.
    api_response = api_instance.configure(access_id, access_key=access_key, access_type=access_type, ldap_proxy_url=ldap_proxy_url, azure_ad_object_id=azure_ad_object_id)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->configure: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **access_id** | **str**| Access ID | 
 **access_key** | **str**| Access Key | [optional] 
 **access_type** | **str**| Access Type (api_key/azure_ad/okta_saml/ldap) | [optional] 
 **ldap_proxy_url** | **str**| Address URL for ldap proxy (relevant only for access-type&#x3D;ldap) | [optional] 
 **azure_ad_object_id** | **str**| Azure Active Directory ObjectId (relevant only for access-type&#x3D;azure_ad) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_auth_method**
> ReplyObj create_auth_method(name, token, access_expires=access_expires, bound_ips=bound_ips)

Create a new Auth Method in the account

Create a new Auth Method in the account Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist with the IPs that the access is restricted to   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Auth Method name
token = 'token_example' # str | Access token
access_expires = 'access_expires_example' # str | Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
bound_ips = 'bound_ips_example' # str | A CIDR whitelist with the IPs that the access is restricted to (optional)

try:
    # Create a new Auth Method in the account
    api_response = api_instance.create_auth_method(name, token, access_expires=access_expires, bound_ips=bound_ips)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_auth_method: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Auth Method name | 
 **token** | **str**| Access token | 
 **access_expires** | **str**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **str**| A CIDR whitelist with the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_auth_method_azure_ad**
> ReplyObj create_auth_method_azure_ad(name, bound_tenant_id, token, access_expires=access_expires, bound_ips=bound_ips, issuer=issuer, jwks_uri=jwks_uri, audience=audience, bound_spid=bound_spid, bound_group_id=bound_group_id, bound_sub_id=bound_sub_id, bound_rg_id=bound_rg_id, bound_providers=bound_providers, bound_resource_types=bound_resource_types, bound_resource_names=bound_resource_names, bound_resource_id=bound_resource_id)

Create a new Auth Method that will be able to authentication using Azure Active Directory credentials

Create a new Auth Method that will be able to authentication using Azure Active Directory credentials Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   bound-tenant-id -    The Azure tenant id that the access is restricted to   issuer -    Issuer URL   jwks-uri -    The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.   audience -    The audience in the JWT   bound-spid -    A list of service principal IDs that the access is restricted to   bound-group-id -    A list of group ids that the access is restricted to   bound-sub-id -    A list of subscription ids that the access is restricted to   bound-rg-id -    A list of resource groups that the access is restricted to   bound-providers -    A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc)   bound-resource-types -    A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc)   bound-resource-names -    A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc).   bound-resource-id -    A list of full resource ids that the access is restricted to   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Auth Method name
bound_tenant_id = 'bound_tenant_id_example' # str | The Azure tenant id that the access is restricted to
token = 'token_example' # str | Access token
access_expires = 'access_expires_example' # str | Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
bound_ips = 'bound_ips_example' # str | A CIDR whitelist of the IPs that the access is restricted to (optional)
issuer = 'issuer_example' # str | Issuer URL (optional)
jwks_uri = 'jwks_uri_example' # str | The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server. (optional)
audience = 'audience_example' # str | The audience in the JWT (optional)
bound_spid = 'bound_spid_example' # str | A list of service principal IDs that the access is restricted to (optional)
bound_group_id = 'bound_group_id_example' # str | A list of group ids that the access is restricted to (optional)
bound_sub_id = 'bound_sub_id_example' # str | A list of subscription ids that the access is restricted to (optional)
bound_rg_id = 'bound_rg_id_example' # str | A list of resource groups that the access is restricted to (optional)
bound_providers = 'bound_providers_example' # str | A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc) (optional)
bound_resource_types = 'bound_resource_types_example' # str | A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc) (optional)
bound_resource_names = 'bound_resource_names_example' # str | A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc). (optional)
bound_resource_id = 'bound_resource_id_example' # str | A list of full resource ids that the access is restricted to (optional)

try:
    # Create a new Auth Method that will be able to authentication using Azure Active Directory credentials
    api_response = api_instance.create_auth_method_azure_ad(name, bound_tenant_id, token, access_expires=access_expires, bound_ips=bound_ips, issuer=issuer, jwks_uri=jwks_uri, audience=audience, bound_spid=bound_spid, bound_group_id=bound_group_id, bound_sub_id=bound_sub_id, bound_rg_id=bound_rg_id, bound_providers=bound_providers, bound_resource_types=bound_resource_types, bound_resource_names=bound_resource_names, bound_resource_id=bound_resource_id)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_auth_method_azure_ad: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Auth Method name | 
 **bound_tenant_id** | **str**| The Azure tenant id that the access is restricted to | 
 **token** | **str**| Access token | 
 **access_expires** | **str**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **str**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 
 **issuer** | **str**| Issuer URL | [optional] 
 **jwks_uri** | **str**| The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server. | [optional] 
 **audience** | **str**| The audience in the JWT | [optional] 
 **bound_spid** | **str**| A list of service principal IDs that the access is restricted to | [optional] 
 **bound_group_id** | **str**| A list of group ids that the access is restricted to | [optional] 
 **bound_sub_id** | **str**| A list of subscription ids that the access is restricted to | [optional] 
 **bound_rg_id** | **str**| A list of resource groups that the access is restricted to | [optional] 
 **bound_providers** | **str**| A list of resource providers that the access is restricted to (e.g, Microsoft.Compute, Microsoft.ManagedIdentity, etc) | [optional] 
 **bound_resource_types** | **str**| A list of resource types that the access is restricted to (e.g, virtualMachines, userAssignedIdentities, etc) | [optional] 
 **bound_resource_names** | **str**| A list of resource names that the access is restricted to (e.g, a virtual machine name, scale set name, etc). | [optional] 
 **bound_resource_id** | **str**| A list of full resource ids that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_auth_method_ldap**
> ReplyObj create_auth_method_ldap(name, public_key_file_path, token, access_expires=access_expires, bound_ips=bound_ips)

Create a new Auth Method that will be able to authentication using LDAP

Create a new Auth Method that will be able to authentication using LDAP Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   public-key-file-path -    A public key generated for LDAP authentication method on Akeyless [RSA2048]   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Auth Method name
public_key_file_path = 'public_key_file_path_example' # str | A public key generated for LDAP authentication method on Akeyless [RSA2048]
token = 'token_example' # str | Access token
access_expires = 'access_expires_example' # str | Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
bound_ips = 'bound_ips_example' # str | A CIDR whitelist of the IPs that the access is restricted to (optional)

try:
    # Create a new Auth Method that will be able to authentication using LDAP
    api_response = api_instance.create_auth_method_ldap(name, public_key_file_path, token, access_expires=access_expires, bound_ips=bound_ips)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_auth_method_ldap: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Auth Method name | 
 **public_key_file_path** | **str**| A public key generated for LDAP authentication method on Akeyless [RSA2048] | 
 **token** | **str**| Access token | 
 **access_expires** | **str**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **str**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_auth_method_oauth2**
> ReplyObj create_auth_method_oauth2(name, bound_clients_ids, issuer, jwks_uri, audience, token, access_expires=access_expires, bound_ips=bound_ips)

Create a new Auth Method that will be able to authentication using OpenId/OAuth2

Create a new Auth Method that will be able to authentication using OpenId/OAuth2 Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   bound-clients-ids -    The clients ids that the access is restricted to   issuer -    Issuer URL   jwks-uri -    The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.   audience -    The audience in the JWT   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Auth Method name
bound_clients_ids = 'bound_clients_ids_example' # str | The clients ids that the access is restricted to
issuer = 'issuer_example' # str | Issuer URL
jwks_uri = 'jwks_uri_example' # str | The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server.
audience = 'audience_example' # str | The audience in the JWT
token = 'token_example' # str | Access token
access_expires = 'access_expires_example' # str | Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
bound_ips = 'bound_ips_example' # str | A CIDR whitelist of the IPs that the access is restricted to (optional)

try:
    # Create a new Auth Method that will be able to authentication using OpenId/OAuth2
    api_response = api_instance.create_auth_method_oauth2(name, bound_clients_ids, issuer, jwks_uri, audience, token, access_expires=access_expires, bound_ips=bound_ips)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_auth_method_oauth2: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Auth Method name | 
 **bound_clients_ids** | **str**| The clients ids that the access is restricted to | 
 **issuer** | **str**| Issuer URL | 
 **jwks_uri** | **str**| The URL to the JSON Web Key Set (JWKS) that containing the public keys that should be used to verify any JSON Web Token (JWT) issued by the authorization server. | 
 **audience** | **str**| The audience in the JWT | 
 **token** | **str**| Access token | 
 **access_expires** | **str**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **str**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_auth_method_saml**
> ReplyObj create_auth_method_saml(name, idp_metadata_url, token, access_expires=access_expires, bound_ips=bound_ips)

Create a new Auth Method that will be able to authentication using SAML

Create a new Auth Method that will be able to authentication using SAML Options:   name -    Auth Method name   access-expires -    Access expiration date in Unix timestamp (select 0 for access without expiry date)   bound-ips -    A CIDR whitelist of the IPs that the access is restricted to   idp-metadata-url -    IDP metadata url   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Auth Method name
idp_metadata_url = 'idp_metadata_url_example' # str | IDP metadata url
token = 'token_example' # str | Access token
access_expires = 'access_expires_example' # str | Access expiration date in Unix timestamp (select 0 for access without expiry date) (optional)
bound_ips = 'bound_ips_example' # str | A CIDR whitelist of the IPs that the access is restricted to (optional)

try:
    # Create a new Auth Method that will be able to authentication using SAML
    api_response = api_instance.create_auth_method_saml(name, idp_metadata_url, token, access_expires=access_expires, bound_ips=bound_ips)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_auth_method_saml: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Auth Method name | 
 **idp_metadata_url** | **str**| IDP metadata url | 
 **token** | **str**| Access token | 
 **access_expires** | **str**| Access expiration date in Unix timestamp (select 0 for access without expiry date) | [optional] 
 **bound_ips** | **str**| A CIDR whitelist of the IPs that the access is restricted to | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_dynamic_secret**
> ReplyObj create_dynamic_secret(name, token, metadata=metadata, key=key)

Creates a new dynamic secret item

Creates a new dynamic secret item Options:   name -    Dynamic secret name   metadata -    Metadata about the dynamic secret   key -    The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used)   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Dynamic secret name
token = 'token_example' # str | Access token
metadata = 'metadata_example' # str | Metadata about the dynamic secret (optional)
key = 'key_example' # str | The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used) (optional)

try:
    # Creates a new dynamic secret item
    api_response = api_instance.create_dynamic_secret(name, token, metadata=metadata, key=key)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_dynamic_secret: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Dynamic secret name | 
 **token** | **str**| Access token | 
 **metadata** | **str**| Metadata about the dynamic secret | [optional] 
 **key** | **str**| The name of a key that used to encrypt the dynamic secret values (if empty, the account default protectionKey key will be used) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_key**
> ReplyObj create_key(name, alg, token, metadata=metadata, split_level=split_level, customer_frg_id=customer_frg_id)

Creates a new key

Creates a new key Options:   name -    Key name   alg -    Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048]   metadata -    Metadata about the key   split-level -    The number of fragments that the item will be split into (not includes customer fragment)   customer-frg-id -    The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment)   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Key name
alg = 'alg_example' # str | Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048]
token = 'token_example' # str | Access token
metadata = 'metadata_example' # str | Metadata about the key (optional)
split_level = 'split_level_example' # str | The number of fragments that the item will be split into (not includes customer fragment) (optional)
customer_frg_id = 'customer_frg_id_example' # str | The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment) (optional)

try:
    # Creates a new key
    api_response = api_instance.create_key(name, alg, token, metadata=metadata, split_level=split_level, customer_frg_id=customer_frg_id)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_key: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Key name | 
 **alg** | **str**| Key type. options- [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048] | 
 **token** | **str**| Access token | 
 **metadata** | **str**| Metadata about the key | [optional] 
 **split_level** | **str**| The number of fragments that the item will be split into (not includes customer fragment) | [optional] 
 **customer_frg_id** | **str**| The customer fragment ID that will be used to create the key (if empty, the key will be created independently of a customer fragment) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_role**
> ReplyObj create_role(name, token, comment=comment)

Creates a new role

Creates a new role Options:   name -    Role name   comment -    Comment about the role   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Role name
token = 'token_example' # str | Access token
comment = 'comment_example' # str | Comment about the role (optional)

try:
    # Creates a new role
    api_response = api_instance.create_role(name, token, comment=comment)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_role: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Role name | 
 **token** | **str**| Access token | 
 **comment** | **str**| Comment about the role | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_secret**
> ReplyObj create_secret(name, value, token, metadata=metadata, key=key, multiline=multiline)

Creates a new secret item

Creates a new secret item Options:   name -    Secret name   value -    The secret value   metadata -    Metadata about the secret   key -    The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)   multiline -    The provided value is a multiline value (separated by '\\n')   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Secret name
value = 'value_example' # str | The secret value
token = 'token_example' # str | Access token
metadata = 'metadata_example' # str | Metadata about the secret (optional)
key = 'key_example' # str | The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) (optional)
multiline = true # bool | The provided value is a multiline value (separated by '\\n') (optional)

try:
    # Creates a new secret item
    api_response = api_instance.create_secret(name, value, token, metadata=metadata, key=key, multiline=multiline)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_secret: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Secret name | 
 **value** | **str**| The secret value | 
 **token** | **str**| Access token | 
 **metadata** | **str**| Metadata about the secret | [optional] 
 **key** | **str**| The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) | [optional] 
 **multiline** | **bool**| The provided value is a multiline value (separated by &#39;\\n&#39;) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **create_ssh_cert_issuer**
> ReplyObj create_ssh_cert_issuer(name, signer_key_name, allowed_users, expiration_sec, token, principals=principals, extensions=extensions, metadata=metadata)

Creates a new SSH certificate issuer

Creates a new SSH certificate issuer Options:   name -    SSH certificate issuer name   signer-key-name -    A key to sign the certificate with   allowed-users -    Users allowed to fetch the certificate, ex. root,ubuntu   principals -    Signed certificates with principal, ex. example_role1,example_role2   extensions -    Signed certificates with extensions, ex. permit-port-forwarding=\"\"   expiration-sec -    Signed certificates with expiration, use second units   metadata -    A metadata about the issuer   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | SSH certificate issuer name
signer_key_name = 'signer_key_name_example' # str | A key to sign the certificate with
allowed_users = 'allowed_users_example' # str | Users allowed to fetch the certificate, ex. root,ubuntu
expiration_sec = 'expiration_sec_example' # str | Signed certificates with expiration, use second units
token = 'token_example' # str | Access token
principals = 'principals_example' # str | Signed certificates with principal, ex. example_role1,example_role2 (optional)
extensions = 'extensions_example' # str | Signed certificates with extensions, ex. permit-port-forwarding=\"\" (optional)
metadata = 'metadata_example' # str | A metadata about the issuer (optional)

try:
    # Creates a new SSH certificate issuer
    api_response = api_instance.create_ssh_cert_issuer(name, signer_key_name, allowed_users, expiration_sec, token, principals=principals, extensions=extensions, metadata=metadata)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->create_ssh_cert_issuer: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| SSH certificate issuer name | 
 **signer_key_name** | **str**| A key to sign the certificate with | 
 **allowed_users** | **str**| Users allowed to fetch the certificate, ex. root,ubuntu | 
 **expiration_sec** | **str**| Signed certificates with expiration, use second units | 
 **token** | **str**| Access token | 
 **principals** | **str**| Signed certificates with principal, ex. example_role1,example_role2 | [optional] 
 **extensions** | **str**| Signed certificates with extensions, ex. permit-port-forwarding&#x3D;\&quot;\&quot; | [optional] 
 **metadata** | **str**| A metadata about the issuer | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **decrypt**
> ReplyObj decrypt(key_name, ciphertext, token, encryption_context=encryption_context)

Decrypts ciphertext into plaintext by using an AES key

Decrypts ciphertext into plaintext by using an AES key Options:   key-name -    The name of the key to use in the decryption process   ciphertext -    Ciphertext to be decrypted in base64 encoded format   encryption-context -    The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
key_name = 'key_name_example' # str | The name of the key to use in the decryption process
ciphertext = 'ciphertext_example' # str | Ciphertext to be decrypted in base64 encoded format
token = 'token_example' # str | Access token
encryption_context = 'encryption_context_example' # str | The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail (optional)

try:
    # Decrypts ciphertext into plaintext by using an AES key
    api_response = api_instance.decrypt(key_name, ciphertext, token, encryption_context=encryption_context)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->decrypt: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **str**| The name of the key to use in the decryption process | 
 **ciphertext** | **str**| Ciphertext to be decrypted in base64 encoded format | 
 **token** | **str**| Access token | 
 **encryption_context** | **str**| The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **decrypt_file**
> ReplyObj decrypt_file(key_name, _in, token, out=out, encryption_context=encryption_context)

Decrypts a file by using an AES key

Decrypts a file by using an AES key Options:   key-name -    The name of the key to use in the decryption process   in -    Path to the file to be decrypted. If not provided, the content will be taken from stdin   out -    Path to the output file. If not provided, the output will be sent to stdout   encryption-context -    The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
key_name = 'key_name_example' # str | The name of the key to use in the decryption process
_in = '_in_example' # str | Path to the file to be decrypted. If not provided, the content will be taken from stdin
token = 'token_example' # str | Access token
out = 'out_example' # str | Path to the output file. If not provided, the output will be sent to stdout (optional)
encryption_context = 'encryption_context_example' # str | The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail (optional)

try:
    # Decrypts a file by using an AES key
    api_response = api_instance.decrypt_file(key_name, _in, token, out=out, encryption_context=encryption_context)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->decrypt_file: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **str**| The name of the key to use in the decryption process | 
 **_in** | **str**| Path to the file to be decrypted. If not provided, the content will be taken from stdin | 
 **token** | **str**| Access token | 
 **out** | **str**| Path to the output file. If not provided, the output will be sent to stdout | [optional] 
 **encryption_context** | **str**| The encryption context. If this was specified in the encrypt command, it must be specified here or the decryption operation will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **decrypt_pkcs1**
> ReplyObj decrypt_pkcs1(key_name, ciphertext, token)

Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5

Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the decryption process   ciphertext -    Ciphertext to be decrypted in base64 encoded format   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
key_name = 'key_name_example' # str | The name of the RSA key to use in the decryption process
ciphertext = 'ciphertext_example' # str | Ciphertext to be decrypted in base64 encoded format
token = 'token_example' # str | Access token

try:
    # Decrypts a plaintext using RSA and the padding scheme from PKCS#1 v1.5
    api_response = api_instance.decrypt_pkcs1(key_name, ciphertext, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->decrypt_pkcs1: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **str**| The name of the RSA key to use in the decryption process | 
 **ciphertext** | **str**| Ciphertext to be decrypted in base64 encoded format | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_assoc**
> ReplyObj delete_assoc(assoc_id, token)

Delete an association between role and auth method

Delete an association between role and auth method Options:   assoc-id -    The association id to be deleted   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
assoc_id = 'assoc_id_example' # str | The association id to be deleted
token = 'token_example' # str | Access token

try:
    # Delete an association between role and auth method
    api_response = api_instance.delete_assoc(assoc_id, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->delete_assoc: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **assoc_id** | **str**| The association id to be deleted | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_auth_method**
> ReplyObj delete_auth_method(name, token)

Delete the Auth Method

Delete the Auth Method Options:   name -    Auth Method name   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Auth Method name
token = 'token_example' # str | Access token

try:
    # Delete the Auth Method
    api_response = api_instance.delete_auth_method(name, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->delete_auth_method: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Auth Method name | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_item**
> ReplyObj delete_item(name, token)

Delete an item

Delete an item Options:   name -    Item name   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Item name
token = 'token_example' # str | Access token

try:
    # Delete an item
    api_response = api_instance.delete_item(name, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->delete_item: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Item name | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_role**
> ReplyObj delete_role(name, token)

Delete a role

Delete a role Options:   name -    Role name   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Role name
token = 'token_example' # str | Access token

try:
    # Delete a role
    api_response = api_instance.delete_role(name, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->delete_role: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Role name | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **delete_role_rule**
> ReplyObj delete_role_rule(role_name, path, token)

Delete a rule from a role

Delete a rule from a role Options:   role-name -    The role name to be updated   path -    The path the rule refers to   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
role_name = 'role_name_example' # str | The role name to be updated
path = 'path_example' # str | The path the rule refers to
token = 'token_example' # str | Access token

try:
    # Delete a rule from a role
    api_response = api_instance.delete_role_rule(role_name, path, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->delete_role_rule: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **role_name** | **str**| The role name to be updated | 
 **path** | **str**| The path the rule refers to | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **describe_item**
> ReplyObj describe_item(name, token)

Returns the item details

Returns the item details Options:   name -    Item name   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Item name
token = 'token_example' # str | Access token

try:
    # Returns the item details
    api_response = api_instance.describe_item(name, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->describe_item: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Item name | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **encrypt**
> ReplyObj encrypt(key_name, plaintext, token, encryption_context=encryption_context)

Encrypts plaintext into ciphertext by using an AES key

Encrypts plaintext into ciphertext by using an AES key Options:   key-name -    The name of the key to use in the encryption process   plaintext -    Data to be encrypted   encryption-context -    name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
key_name = 'key_name_example' # str | The name of the key to use in the encryption process
plaintext = 'plaintext_example' # str | Data to be encrypted
token = 'token_example' # str | Access token
encryption_context = 'encryption_context_example' # str | name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail (optional)

try:
    # Encrypts plaintext into ciphertext by using an AES key
    api_response = api_instance.encrypt(key_name, plaintext, token, encryption_context=encryption_context)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->encrypt: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **str**| The name of the key to use in the encryption process | 
 **plaintext** | **str**| Data to be encrypted | 
 **token** | **str**| Access token | 
 **encryption_context** | **str**| name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **encrypt_file**
> ReplyObj encrypt_file(key_name, _in, token, out=out, encryption_context=encryption_context)

Encrypts a file by using an AES key

Encrypts a file by using an AES key Options:   key-name -    The name of the key to use in the encryption process   in -    Path to the file to be encrypted. If not provided, the content will be taken from stdin   out -    Path to the output file. If not provided, the output will be sent to stdout   encryption-context -    name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
key_name = 'key_name_example' # str | The name of the key to use in the encryption process
_in = '_in_example' # str | Path to the file to be encrypted. If not provided, the content will be taken from stdin
token = 'token_example' # str | Access token
out = 'out_example' # str | Path to the output file. If not provided, the output will be sent to stdout (optional)
encryption_context = 'encryption_context_example' # str | name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail (optional)

try:
    # Encrypts a file by using an AES key
    api_response = api_instance.encrypt_file(key_name, _in, token, out=out, encryption_context=encryption_context)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->encrypt_file: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **str**| The name of the key to use in the encryption process | 
 **_in** | **str**| Path to the file to be encrypted. If not provided, the content will be taken from stdin | 
 **token** | **str**| Access token | 
 **out** | **str**| Path to the output file. If not provided, the output will be sent to stdout | [optional] 
 **encryption_context** | **str**| name-value pair that specifies the encryption context to be used for authenticated encryption. If used here, the same value must be supplied to the decrypt command or decryption will fail | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **encrypt_pkcs1**
> ReplyObj encrypt_pkcs1(key_name, plaintext, token)

Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5

Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the encryption process   plaintext -    Data to be encrypted   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
key_name = 'key_name_example' # str | The name of the RSA key to use in the encryption process
plaintext = 'plaintext_example' # str | Data to be encrypted
token = 'token_example' # str | Access token

try:
    # Encrypts the given message with RSA and the padding scheme from PKCS#1 v1.5
    api_response = api_instance.encrypt_pkcs1(key_name, plaintext, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->encrypt_pkcs1: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **str**| The name of the RSA key to use in the encryption process | 
 **plaintext** | **str**| Data to be encrypted | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_auth_method**
> ReplyObj get_auth_method(name, token)

Returns an information about the Auth Method

Returns an information about the Auth Method Options:   name -    Auth Method name   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Auth Method name
token = 'token_example' # str | Access token

try:
    # Returns an information about the Auth Method
    api_response = api_instance.get_auth_method(name, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->get_auth_method: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Auth Method name | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_dynamic_secret_value**
> ReplyObj get_dynamic_secret_value(name, token)

Get dynamic secret value

Get dynamic secret value Options:   name -    Dynamic secret name   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Dynamic secret name
token = 'token_example' # str | Access token

try:
    # Get dynamic secret value
    api_response = api_instance.get_dynamic_secret_value(name, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->get_dynamic_secret_value: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Dynamic secret name | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_role**
> ReplyObj get_role(name, token)

Get role details

Get role details Options:   name -    Role name   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Role name
token = 'token_example' # str | Access token

try:
    # Get role details
    api_response = api_instance.get_role(name, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->get_role: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Role name | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_rsa_public**
> ReplyObj get_rsa_public(name, token)

Obtain the public key from a specific RSA private key

Obtain the public key from a specific RSA private key Options:   name -    Name of key to be created   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Name of key to be created
token = 'token_example' # str | Access token

try:
    # Obtain the public key from a specific RSA private key
    api_response = api_instance.get_rsa_public(name, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->get_rsa_public: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Name of key to be created | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_secret_value**
> ReplyObj get_secret_value(name, token)

Get static secret value

Get static secret value Options:   name -    Secret name   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Secret name
token = 'token_example' # str | Access token

try:
    # Get static secret value
    api_response = api_instance.get_secret_value(name, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->get_secret_value: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Secret name | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **get_ssh_certificate**
> ReplyObj get_ssh_certificate(cert_username, cert_issuer_name, public_key_file_path, token)

Generates SSH certificate

Generates SSH certificate Options:   cert-username -    The username to sign in the SSH certificate   cert-issuer-name -    The name of the SSH certificate issuer   public-key-file-path -    SSH public key   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
cert_username = 'cert_username_example' # str | The username to sign in the SSH certificate
cert_issuer_name = 'cert_issuer_name_example' # str | The name of the SSH certificate issuer
public_key_file_path = 'public_key_file_path_example' # str | SSH public key
token = 'token_example' # str | Access token

try:
    # Generates SSH certificate
    api_response = api_instance.get_ssh_certificate(cert_username, cert_issuer_name, public_key_file_path, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->get_ssh_certificate: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **cert_username** | **str**| The username to sign in the SSH certificate | 
 **cert_issuer_name** | **str**| The name of the SSH certificate issuer | 
 **public_key_file_path** | **str**| SSH public key | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **help**
> ReplyObj help()

help text

help text

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()

try:
    # help text
    api_response = api_instance.help()
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->help: %s\n" % e)
```

### Parameters
This endpoint does not need any parameter.

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_auth_methods**
> ReplyObj list_auth_methods(token)

Returns a list of all the Auth Methods in the account

Returns a list of all the Auth Methods in the account Options:   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
token = 'token_example' # str | Access token

try:
    # Returns a list of all the Auth Methods in the account
    api_response = api_instance.list_auth_methods(token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->list_auth_methods: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_items**
> ReplyObj list_items(token, type=type, items_types=items_types, path=path)

Returns a list of all accessible items

Returns a list of all accessible items Options:   type -    The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret]   ItemsTypes -    ItemsTypes   path -    Path to folder   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
token = 'token_example' # str | Access token
type = 'type_example' # str | The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret] (optional)
items_types = 'items_types_example' # str | ItemsTypes (optional)
path = 'path_example' # str | Path to folder (optional)

try:
    # Returns a list of all accessible items
    api_response = api_instance.list_items(token, type=type, items_types=items_types, path=path)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->list_items: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **str**| Access token | 
 **type** | **str**| The item types list of the requested items. In case it is empty, all types of items will be returned. options- [key, static-secret, dynamic-secret] | [optional] 
 **items_types** | **str**| ItemsTypes | [optional] 
 **path** | **str**| Path to folder | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **list_roles**
> ReplyObj list_roles(token)

Returns a list of all roles in the account

Returns a list of all roles in the account Options:   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
token = 'token_example' # str | Access token

try:
    # Returns a list of all roles in the account
    api_response = api_instance.list_roles(token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->list_roles: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **set_role_rule**
> ReplyObj set_role_rule(role_name, path, capability, token)

Set a rule to a role

Set a rule to a role Options:   role-name -    The role name to be updated   path -    The path the rule refers to   capability -    List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny]   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
role_name = 'role_name_example' # str | The role name to be updated
path = 'path_example' # str | The path the rule refers to
capability = 'capability_example' # str | List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny]
token = 'token_example' # str | Access token

try:
    # Set a rule to a role
    api_response = api_instance.set_role_rule(role_name, path, capability, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->set_role_rule: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **role_name** | **str**| The role name to be updated | 
 **path** | **str**| The path the rule refers to | 
 **capability** | **str**| List of the approved/denied capabilities in the path options- [read, create, update, delete, list, deny] | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **sign_pkcs1**
> ReplyObj sign_pkcs1(key_name, message, token)

Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5

Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5 Options:   key-name -    The name of the RSA key to use in the signing process   message -    The message to be signed   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
key_name = 'key_name_example' # str | The name of the RSA key to use in the signing process
message = 'message_example' # str | The message to be signed
token = 'token_example' # str | Access token

try:
    # Calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS#1 v1.5
    api_response = api_instance.sign_pkcs1(key_name, message, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->sign_pkcs1: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **str**| The name of the RSA key to use in the signing process | 
 **message** | **str**| The message to be signed | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **unconfigure**
> ReplyObj unconfigure(token)

Remove Configuration of client profile.

Remove Configuration of client profile. Options:   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
token = 'token_example' # str | Access token

try:
    # Remove Configuration of client profile.
    api_response = api_instance.unconfigure(token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->unconfigure: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **update_item**
> ReplyObj update_item(name, token, new_name=new_name, new_metadata=new_metadata)

Update item name and metadata

Update item name and metadata Options:   name -    Current item name   new-name -    New item name   new-metadata -    New item metadata   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Current item name
token = 'token_example' # str | Access token
new_name = 'new_name_example' # str | New item name (optional)
new_metadata = 'new_metadata_example' # str | New item metadata (optional)

try:
    # Update item name and metadata
    api_response = api_instance.update_item(name, token, new_name=new_name, new_metadata=new_metadata)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->update_item: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Current item name | 
 **token** | **str**| Access token | 
 **new_name** | **str**| New item name | [optional] 
 **new_metadata** | **str**| New item metadata | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **update_role**
> ReplyObj update_role(name, token, new_name=new_name, new_comment=new_comment)

Update role details

Update role details Options:   name -    Role name   new-name -    New Role name   new-comment -    New comment about the role   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Role name
token = 'token_example' # str | Access token
new_name = 'new_name_example' # str | New Role name (optional)
new_comment = 'new_comment_example' # str | New comment about the role (optional)

try:
    # Update role details
    api_response = api_instance.update_role(name, token, new_name=new_name, new_comment=new_comment)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->update_role: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Role name | 
 **token** | **str**| Access token | 
 **new_name** | **str**| New Role name | [optional] 
 **new_comment** | **str**| New comment about the role | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **update_secret_val**
> ReplyObj update_secret_val(name, value, token, key=key, multiline=multiline)

Update static secret value

Update static secret value Options:   name -    Secret name   value -    The new secret value   key -    The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)   multiline -    The provided value is a multiline value (separated by '\\n')   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Secret name
value = 'value_example' # str | The new secret value
token = 'token_example' # str | Access token
key = 'key_example' # str | The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) (optional)
multiline = true # bool | The provided value is a multiline value (separated by '\\n') (optional)

try:
    # Update static secret value
    api_response = api_instance.update_secret_val(name, value, token, key=key, multiline=multiline)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->update_secret_val: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Secret name | 
 **value** | **str**| The new secret value | 
 **token** | **str**| Access token | 
 **key** | **str**| The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used) | [optional] 
 **multiline** | **bool**| The provided value is a multiline value (separated by &#39;\\n&#39;) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **upload_pkcs12**
> ReplyObj upload_pkcs12(name, _in, passphrase, token, metadata=metadata, split_level=split_level, customer_frg_id=customer_frg_id, cert=cert)

Upload a PKCS#12 key and certificates

Upload a PKCS#12 key and certificates Options:   name -    Name of key to be created   in -    PKCS#12 input file (private key and certificate only)   passphrase -    Passphrase to unlock the pkcs#12 bundle   metadata -    A metadata about the key   split-level -    The number of fragments that the item will be split into   customer-frg-id -    The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)   cert -    Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Name of key to be created
_in = '_in_example' # str | PKCS#12 input file (private key and certificate only)
passphrase = 'passphrase_example' # str | Passphrase to unlock the pkcs#12 bundle
token = 'token_example' # str | Access token
metadata = 'metadata_example' # str | A metadata about the key (optional)
split_level = 'split_level_example' # str | The number of fragments that the item will be split into (optional)
customer_frg_id = 'customer_frg_id_example' # str | The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) (optional)
cert = 'cert_example' # str | Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file (optional)

try:
    # Upload a PKCS#12 key and certificates
    api_response = api_instance.upload_pkcs12(name, _in, passphrase, token, metadata=metadata, split_level=split_level, customer_frg_id=customer_frg_id, cert=cert)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->upload_pkcs12: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Name of key to be created | 
 **_in** | **str**| PKCS#12 input file (private key and certificate only) | 
 **passphrase** | **str**| Passphrase to unlock the pkcs#12 bundle | 
 **token** | **str**| Access token | 
 **metadata** | **str**| A metadata about the key | [optional] 
 **split_level** | **str**| The number of fragments that the item will be split into | [optional] 
 **customer_frg_id** | **str**| The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) | [optional] 
 **cert** | **str**| Path to a file that contain the certificate in a PEM format. If this parameter is not empty, the certificate will be taken from here and not from the PKCS#12 input file | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **upload_rsa**
> ReplyObj upload_rsa(name, alg, rsa_key_file_path, token, metadata=metadata, split_level=split_level, customer_frg_id=customer_frg_id)

Upload RSA key

Upload RSA key Options:   name -    Name of key to be created   alg -    Key type. options- [RSA1024, RSA2048]   rsa-key-file-path -    RSA private key file path   metadata -    A metadata about the key   split-level -    The number of fragments that the item will be split into   customer-frg-id -    The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment)   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
name = 'name_example' # str | Name of key to be created
alg = 'alg_example' # str | Key type. options- [RSA1024, RSA2048]
rsa_key_file_path = 'rsa_key_file_path_example' # str | RSA private key file path
token = 'token_example' # str | Access token
metadata = 'metadata_example' # str | A metadata about the key (optional)
split_level = 'split_level_example' # str | The number of fragments that the item will be split into (optional)
customer_frg_id = 'customer_frg_id_example' # str | The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) (optional)

try:
    # Upload RSA key
    api_response = api_instance.upload_rsa(name, alg, rsa_key_file_path, token, metadata=metadata, split_level=split_level, customer_frg_id=customer_frg_id)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->upload_rsa: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **name** | **str**| Name of key to be created | 
 **alg** | **str**| Key type. options- [RSA1024, RSA2048] | 
 **rsa_key_file_path** | **str**| RSA private key file path | 
 **token** | **str**| Access token | 
 **metadata** | **str**| A metadata about the key | [optional] 
 **split_level** | **str**| The number of fragments that the item will be split into | [optional] 
 **customer_frg_id** | **str**| The customer fragment ID that will be used to split the key (if empty, the key will be created independently of a customer fragment) | [optional] 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **verify_pkcs1**
> ReplyObj verify_pkcs1(key_name, message, signature, token)

Verifies an RSA PKCS#1 v1.5 signature

Verifies an RSA PKCS#1 v1.5 signature Options:   key-name -    The name of the RSA key to use in the verification process   message -    The message to be verified   signature -    The message's signature   token -    Access token

### Example
```python
from __future__ import print_function
import time
import akeyless_proxy_api
from akeyless_proxy_api.rest import ApiException
from pprint import pprint

# create an instance of the API class
api_instance = akeyless_proxy_api.DefaultApi()
key_name = 'key_name_example' # str | The name of the RSA key to use in the verification process
message = 'message_example' # str | The message to be verified
signature = 'signature_example' # str | The message's signature
token = 'token_example' # str | Access token

try:
    # Verifies an RSA PKCS#1 v1.5 signature
    api_response = api_instance.verify_pkcs1(key_name, message, signature, token)
    pprint(api_response)
except ApiException as e:
    print("Exception when calling DefaultApi->verify_pkcs1: %s\n" % e)
```

### Parameters

Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **key_name** | **str**| The name of the RSA key to use in the verification process | 
 **message** | **str**| The message to be verified | 
 **signature** | **str**| The message&#39;s signature | 
 **token** | **str**| Access token | 

### Return type

[**ReplyObj**](ReplyObj.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

