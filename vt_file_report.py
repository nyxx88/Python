#######################################################################################################################
#######################################################################################################################
#
# Packages to install:
# - "pip install httpx[http2]" (Install httpx with HTTP/2 support)
#
# Usage:
#  - Key parameter is vt_api_key. Its value can be initialized from:
#    - environment variable $VT_APIKEY (if it exists)
#    - key-value pair in a text configuration file with the key VT_APIKEY. Specify the configuration file using the
#      argument "--config_file"
#    - commandline argument "--apikey"
#  - Takes hash values as input in one of the following forms via commandline arguments:
#    - list of hash values in a file using "--hashfile"
#    - a single hash value using "--hashvalue"
#  - Default output is CSV formatted string of:
#    - hash value
#    - malicious count (number of malicious detection by vendors)
#    - undetected count (number of non-malicious detection by vendors)
#  - Optional output is specific verdict by vendors. Specify the list of vendors using the argument "--vendors"
#
#
# Example:
#
#           vt_file_report.py --hashfile hashlist.txt --vendors Abc Def Xyz
#
#   In this case, the vt_api_key is obtained from environment variable, since no configuration file was specified &
#   neither was it passed via a command line argument. Specific detection results for 3 vendors "Abc", "Def" & "Xyz"
#   were requested.
#
#######################################################################################################################
#######################################################################################################################

import argparse
import configparser
import httpx
import os

#######################################################################################################################
# global variables
#######################################################################################################################

##### VirusTotal API invocation
vt_base_url = None
vt_api_key = None

## VirusTotal API calls
hashfile = None
hashvalue = None

## desired output
vendors = None

#######################################################################################################################
# classes
#######################################################################################################################

class vt_api_client:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key

    http_client = httpx.Client(http2=True)

#######################################################################################################################
# functions
#######################################################################################################################

def error_message(str, exception = None):
    if exception is None:
        print(str)
    else:                                                                                                              # expecting an Exception
        print(str, exception)

    exit()

def init_envvar():
    global vt_api_key

    vt_api_key = os.environ.get('VT_APIKEY')

def init_configfile(config_file):
    global vt_api_key

    dummy = ' '
    try:
        with open(config_file) as f:                                                                                   # ConfigParser needs a [section] structure, otherwise it is not happy
            file_content = '[' + dummy +']\n' + f.read()
    except Exception as ex:
        error_message(config_file + ' :', exception = ex)

    config = configparser.RawConfigParser()
    config.read_string(file_content)

    try:
        vt_api_key = config[dummy]['VT_APIKEY']
    except Exception as ex:
        error_message(config_file + ' :', exception = ex)

def init_cli():
    global vt_api_key

    global hashvalue
    global hashfile

    global vendors

    # parse CLI
    parser = argparse.ArgumentParser()

    ##### generic use -- config file
    parser.add_argument('--configfile', help = 'configuration file')

    ##### VirusTotal API invocation
    parser.add_argument('--apikey', help = 'VirusTotal API key')

    ##### VirusTotal API calls
    parser.add_argument('--hashfile', help = 'text file with hashes')
    parser.add_argument('--hashvalue', help = 'hash value')

    ##### desired output
    parser.add_argument('--vendors', nargs = '*', help = 'list of vendors')

    args = parser.parse_args()

    if args.configfile is not None:
        init_configfile(args.configfile)

    if args.apikey is not None:                                                                                        # if API key is provided via command line
        vt_api_key = args.apikey
    elif (vt_api_key is None) or (len(vt_api_key) == 0):                                                               # if API key has never been defined, or is an empty string
        error_message('VirusTotal API key missing.\n')

    if (args.hashvalue is not None) and (args.hashfile is not None):
        error_message('Conflicting hash arguments.\n')

    if args.hashvalue is not None:
        hashvalue = args.hashvalue
    if args.hashfile is not None:
        hashfile = args.hashfile

    if args.vendors is not None:
        vendors = args.vendors

def init_param():
    global vt_base_url

    init_envvar()
    init_cli()
    vt_base_url = 'https://www.virustotal.com'

## API helper #########################################################################################################
def build_api_header(*dicts):
    h = {
            'accept': 'application/json'
        }

    if (len(dicts) > 0):
        for dict in dicts:
            h.update(dict)

    return (h)

## VT API calls #######################################################################################################

def vt_get_a_file_report(api_client, file_hash):                                                                       # get results based on file hash

    api_endpoint = '/api/v3/files/'

    url = api_client.base_url + api_endpoint + file_hash
    h = build_api_header(dict([('x-apikey', api_client.api_key)]))

    try:
        r = api_client.http_client.get(url, headers = h)
        return(r)
    except Exception as ex:
        error_message(url + ' :', exception = ex)

## process the file hashes ############################################################################################

def process_hash(api_client, file_hash, vendors):
    r = vt_get_a_file_report(api_client, file_hash)
    if (r.status_code == 200):
        # print(r.content.decode('utf-8'))                                                                             # returns the content of the response, in bytes. then decode it with UTF-8
        # print(r.text)                                                                                                # returns the content of the response, in unicode
        print(file_hash, end='')

        ## how many malicious & undetected count
        print(', ' + str(r.json()['data']['attributes']['last_analysis_stats']['malicious']), end='')                  # had to cast a returned int value to a string if not the concatenation would fail
        print(', ' + str(r.json()['data']['attributes']['last_analysis_stats']['undetected']), end='')

        ## individual vendor's assessment
        if vendors is not None:
            for vendor in vendors:
                try:
                    vendor_category = r.json()['data']['attributes']['last_analysis_results'][vendor]['category']
                except KeyError as ke:
                    vendor_category = 'unknown'

                print(', ' + vendor_category, end='')

        print('')
    else:
        print(file_hash, end='')
        print(', ERROR: ' + str(r.status_code))

#######################################################################################################################
# main program
#######################################################################################################################

init_param()

vt_client = vt_api_client(vt_base_url, vt_api_key)

if hashvalue is not None:
    process_hash(vt_client, hashvalue.strip(), vendors)

if hashfile is not None:
    try:
        with open(hashfile) as file:
            for file_hash in file:
                process_hash(vt_client, file_hash.strip(), vendors)                                                    # file content comes with newline, which causes problems
    except Exception as ex:
        error_message(hashfile + ' :', exception = ex)
