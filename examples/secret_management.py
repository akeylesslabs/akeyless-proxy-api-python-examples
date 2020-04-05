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
    print("Exception when calling DefaultApi->auth: %s\n" % e)