#######################################################################################################################
#######################################################################################################################
#
# Packages to install:
# - "pip install httpx[http2]" (Install httpx with HTTP/2 support)
#
# Usage:
#  - Key parameters are:
#    - cs_base_url -- Which Falcon cloud the tenant CID is on
#    - cs_client_id -- ID of API client
#    - cs_client_secret -- Secret of API client
#  - These 3 parameters can be initialized from:
#    - environment variables (if they exists):
#      - URL
#      - CLIENT_ID
#      - CLIENT_SECRET
#    - key-value pair in a text configuration file (specified via commandline using argument "--config_file") with the
#      following keys:
#      - URL
#      - CLIENT_ID
#      - CLIENT_SECRET
#    - commandline arguments
#      - "--cs_url"
#      - "--cs_id"
#      - "--cs_secret"
#
# Modify the logic to call the APIs in the main portion of the script (near the bottom) according to your needs.
#
# Note: Usage of the various CrowdStrike APIs are beyond the scope of this script. There are other online resources
#       that are better equipped for that purpose.
#
# Example:
#
#           cs_api.py --configfile config.txt
#
#    The configuration file "config.txt" contains the necessary parameters needed for the API calls to work.
#
#######################################################################################################################
#######################################################################################################################

import argparse
import base64
import configparser
import httpx
import os
import time

#######################################################################################################################
# global variables
#######################################################################################################################

##### CrowdStrike API invocation
cs_base_url = None
cs_client_id = None
cs_client_secret = None

#######################################################################################################################
# classes
#######################################################################################################################

class cs_api_client:
    access_token = None
    time_start = None                                                                                                  # print (time.asctime(time.localtime(api_client.time_start)))

    authenticated_header = None

    http_client = httpx.Client(http2=True)

    def __init__(self, base_url, client_id, client_secret):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret

    ## CS API helpers #################################################################################################
    def cs_generic_get(self, api_endpoint, parameters):
        url = self.base_url + api_endpoint

        if (len(parameters) > 0):
            url = url + '?' + build_http_data(parameters)                                                              # dictionary datatype

        return(self.http_client.get(url, headers = self.authenticated_header))

    def cs_generic_post(self, api_endpoint, data):
        url = self.base_url + api_endpoint

        h = build_http_header(self.authenticated_header, {"Content-Type": "application/json"})

        return(self.http_client.post(url, headers = h, data = data))

    # To cater to 'fussy' APIs, that only accepts double quote characters to enclose the keyword name (the dataname parameter)
    # and also the data (the individual item in items parameter). It also does not tolerate an extra comma at the end of a list of
    # items.
    def cs_post_body_builder(self, dataname, items):
        body = '{ "' + dataname + '": ['

        no_items = len(items)
        if (no_items > 0):
            i = 0

            for item in items:
                body = body + '"' + item + '"'
                i += 1
                if (i < no_items):
                    body = body + ', '

        body = body + ']}'

        return(body)

    ## CS API calls ###################################################################################################

    ##### oauth2

    def cs_auth(self):                                                                                                 # authenticate
        api_endpoint = "/oauth2/token"

        url = self.base_url + api_endpoint
        h = build_http_header({"Content-Type": "application/x-www-form-urlencoded"})
        d = build_http_data({"client_id": self.client_id}, {"client_secret": self.client_secret})                      # tuple datatype

        r = self.http_client.post(url, headers = h, data = d)
        # further enhancement can be done to check if redirection is supported (status code 308)

        if (r.status_code == 201):                                                                                     # successful authentication will return 201
            self.access_token = r.json()["access_token"]
            self.time_start = time.time()
            self.authenticated_header = ({"authorization" : "bearer " + self.access_token})
            return(True)
        else:
            return(False)

    def cs_revoke_auth(self):                                                                                          # revoke access token
        api_endpoint = "/oauth2/revoke"

        url = self.base_url + api_endpoint
        h = build_http_header({"Content-Type": "application/x-www-form-urlencoded"}, {"authorization": "basic " + base64.b64encode(bytes(self.client_id + ":" + self.client_secret, "utf-8")).decode("utf-8")})
        d = build_http_data({"client_id": self.client_id }, {"token": self.access_token})                              # tuple datatype

        r = self.http_client.post(url, headers = h, data = d)
        return (r)

    ##### hosts

    def cs_get_host_ids(self, **parameters):
        api_endpoint = '/devices/queries/devices/v1'

        return(self.cs_generic_get(api_endpoint, parameters))

    ##### intel

    def cs_get_indicators_by_fql(self, **parameters):
        api_endpoint = '/intel/queries/indicators/v1'

        return(self.cs_generic_get(api_endpoint, parameters))

    def cs_get_indicators_info_by_fql(self, **parameters):
        api_endpoint = '/intel/combined/indicators/v1'

        return(self.cs_generic_get(api_endpoint, parameters))

    def cs_indicators(self, ids):
        api_endpoint = '/intel/entities/indicators/GET/v1'

        data = self.cs_post_body_builder('ids', ids)

        return(self.cs_generic_post(api_endpoint, data))

    ##### alerts

    def cs_alerts_by_composite_ids(self, composite_ids):
        api_endpoint = '/alerts/entities/alerts/v2'

        data = self.cs_post_body_builder('composite_ids', composite_ids)

        return(self.cs_generic_post(api_endpoint, data))

    # def cs_alerts_by_composite_ids(self, composite_ids):
    #     api_endpoint = '/alerts/entities/alerts/v2'

    #     data = '{ "composite_ids": ['

    #     no_of_composite_ids = len(composite_ids)
    #     if (no_of_composite_ids > 0):
    #         i = 0

    #         for composite_id in composite_ids:
    #             data = data + '"' + composite_id + '"'
    #             i += 1
    #             if (i < no_of_composite_ids):
    #                 data = data + ', '

    #     data = data + ']}'

    #     return(self.cs_generic_post(api_endpoint, data))

## HTTP helpers #######################################################################################################

def build_http_header(*params):                                                                                        # accepts tuple datatype
    h = {
            "accept": "application/json"
        }

    if (len(params) > 0):
        for param in params:
            h.update(param)

    return (h)

def build_http_data(*params):                                                                                          # accepts tuple datatype
    d = ''

    if (len(params) > 0):
        i = 0

        for param in params:
            for key, value in param.items():
                if (i > 0):
                    d = d + '&'                                                                                        # delimit the parameters

                d = d + key + '=' + str(value)
                i += 1

    return (d)

#######################################################################################################################
# functions
#######################################################################################################################

def error_message(str, exception = None):
    if exception is None:
        print(str)
    else:                                                                                                              # expecting an Exception
        print(str, exception)
    exit()

def has_value(var):
    if (var is None) or (len(var) == 0):
        return(False)
    else:
        return(True)

def init_envvar():
    global cs_base_url
    global cs_client_id
    global cs_client_secret

    cs_base_url = os.environ.get('URL')
    cs_client_id = os.environ.get('CLIENT_ID')
    cs_client_secret = os.environ.get('CLIENT_SECRET')

def init_configfile(config_file):
    global cs_base_url
    global cs_client_id
    global cs_client_secret

    dummy = ' '
    try:
        with open(config_file) as f:                                                                                   # ConfigParser needs a [section] structure, otherwise it is not happy
            file_content = '[' + dummy +']\n' + f.read()
    except Exception as ex:
       error_message(config_file + ' :', exception = ex)

    config = configparser.RawConfigParser()
    config.read_string(file_content)

    try:
        cs_base_url = config[dummy]['URL']
        cs_client_id = config[dummy]['CLIENT_ID']
        cs_client_secret = config[dummy]['CLIENT_SECRET']
    except Exception as ex:
        error_message(config_file + ' :', exception = ex)

def init_cli():
    global cs_base_url
    global cs_client_id
    global cs_client_secret

    # parse CLI
    parser = argparse.ArgumentParser()

    ##### generic use -- config file
    parser.add_argument('--configfile', help = 'configuration file')

    ##### CrowdStrike API invocation
    parser.add_argument('--cs_url', help = 'CrowdStrike API base URL')
    parser.add_argument('--cs_id', help = 'CrowdStrike API client ID')
    parser.add_argument('--cs_secret', help = 'CrowdStrike API client password')

    args = parser.parse_args()

    if args.configfile is not None:
        init_configfile(args.configfile)

    if args.cs_url is not None:
        cs_base_url = args.cs_url
    if args.cs_id is not None:
        cs_client_id = args.cs_id
    if args.cs_secret is not None:
        cs_client_secret = args.cs_secret

    if not ((has_value(cs_base_url)) and (has_value(cs_client_id)) and (has_value(cs_client_secret))):
        error_message('Insufficient arguments to proceed.\n')

def init_param():
    init_envvar()
    init_cli()

#######################################################################################################################
# main program
#######################################################################################################################

init_param()

cs_client = cs_api_client(cs_base_url, cs_client_id, cs_client_secret)

if (cs_client.cs_auth() == False):
    error_message('Authentication failure.\n')

# examples of how to call the API functions

##### List hosts

# r = cs_client.cs_get_host_ids()                                                                                        # API with default parameter values -- returns list of hosts
# r = cs_client.cs_get_host_ids(limit = 3, offset = 2)                                                                   # API with optional parameters values -- returns list of hosts

# if using operators in FQL query, it should be of the form of:
# - parameter, followed by a colon, operator, value in double quotes
# - e.g. published_date:>="2024-01-01T12:00:00Z" (human readable)
# - e.g. published_date%3A%3E%3D"2024-01-03T12%3A00%3A00Z (in code)

##### Threat intel - query indicators by FQL

# r = cs_client.cs_get_indicators_by_fql()                                                                               # API with default parameter values -- returns list of IOCs
# r = cs_client.cs_get_indicators_by_fql(limit = 2, filter = 'type%3A"hash_sha256"')                                     # API with optional parameters values (including simple FQL query to filter the data) -- returns list of IOCs after FQL query filtering
# r = cs_client.cs_get_indicators_by_fql(limit = 500, filter = 'published_date%3A%3E%3D"2024-01-03T12%3A00%3A00Z"')      # API with optional parameters values (including a more complex FQL query to filter the data) -- returns list of IOCs after FQL query filtering
# r = cs_client.cs_get_indicators_info_by_fql(limit = 2, filter = 'type%3A"hash_sha256"')                                # API with optional parameter values -- returns list of IOCs and additional related information

##### Threat intel - query indicators by IDs

r = cs_client.cs_indicators(('hash_sha256_574ec46f739d7145dd47952c81fc51f7b708c495223dc5293788e44ebb40aeeb', 'ip_address_195.123.211.210', 'domain_f3.ttkt.cc'))

##### Alerts

# r = cs_client.cs_alerts_by_composite_ids(('49651999c4e64e18bca87d92dd7d5829:ind:89dc8ecfde364f88a666272f41ed0210:2245537033-10141-8820496', ))               # API to retrieve detection alert details
# r = cs_client.cs_alerts_by_composite_ids(('49651999c4e64e18bca87d92dd7d5829:ind:fb22963210354d57b8c67b76c99b3fbf:4671593601-5702-1216272', ))
# r = cs_client.cs_alerts_by_composite_ids(('49651999c4e64e18bca87d92dd7d5829:ind:caf6d40ace3f422985e805051a9096c7:5272507902-10193-3464464', '49651999c4e64e18bca87d92dd7d5829:ind:181eb79ad3724245b272f019dd03115f:5273998308-5702-2715408'))

if (r.status_code == 200):
    print (r.text)
else:
    # print (r.status_code)
    print(r)

r = cs_client.cs_revoke_auth()
# print (r.status_code)
