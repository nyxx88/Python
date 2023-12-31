#######################################################################################################################
#######################################################################################################################
#
# Packages to install:
# - "pip install httpx[http2]" (Install httpx with HTTP/2 support)
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

def error_message(str):
    print(str)
    exit()

def exception_message(msg, ex):
    print(msg, ex)
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
        exception_message(config_file + ' :', ex)

    config = configparser.RawConfigParser()
    config.read_string(file_content)
    vt_api_key = config[dummy]['VT_APIKEY']

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
    parser.add_argument('--vt_apikey', help = 'VT API key')

    ##### VirusTotal API calls
    parser.add_argument('--hashfile', help = 'text file with hashes')
    parser.add_argument('--hashvalue', help = 'hash value')

    ##### desired utput
    parser.add_argument('--vendors', nargs = '*', help = 'list of vendors')

    args = parser.parse_args()

    if args.configfile is not None:
        init_configfile(args.configfile)

    if args.vt_apikey is not None:
        vt_api_key = args.vt_apikey
    elif (vt_api_key is None) or (len(vt_api_key) == 0):
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
        exception_message(url + ' :', ex)

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
        exception_message(hashfile + ' :', ex)
