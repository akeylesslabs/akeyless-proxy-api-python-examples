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