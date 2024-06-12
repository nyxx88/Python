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
import configparser
import datetime
import httpx
import json
import os
import time

from time import strftime

#######################################################################################################################
# global variables
#######################################################################################################################

##### CrowdStrike HEC
sg_weather_cs_hec_ingest_url = None
sg_weather_cs_hec_api_key = None

##### SG govt data source
sg_gov_data_base_url = None
sg_gov_data_api_endpoint = None

##### Loop control
loop_duration = None                                                                                                   # in minutes
sleep_duration = None                                                                                                  # in minutes

#######################################################################################################################
# classes
#######################################################################################################################

class cs_hec_ingest_client:
    http_client = httpx.Client(http2=True)

    def __init__(self, ingest_url, api_key):
        self.ingest_url = ingest_url
        self.api_key = api_key

        self.header = {"Content-Type": "text/plain; charset=utf-8"}
        self.header.update({"authorization" : "bearer " + self.api_key})

    def send_log(self, log_str):
        return(self.http_client.post(self.ingest_url, headers = self.header, data = log_str))

class sg_gov_data_client:
    http_client = httpx.Client(http2=True)

    def __init__(self, base_url):
        self.base_url = base_url

        self.header = {"accept": "*/*"}

    def query(self, api_endpoint):
        self.url = self.base_url + api_endpoint
        return(self.http_client.get(self.url, headers = self.header))

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
    global sg_weather_cs_hec_ingest_url
    global sg_weather_cs_hec_api_key

    global sg_gov_data_base_url
    global sg_gov_air_temp_endpoint

    global loop_duration
    global sleep_duration

    ##### CrowdStrike HEC on Talon_1
    # API key: xxxxxx
    # Ingest URL: https://ingest.us-1.crowdstrike.com/api/ingest/hec/xxxxxx/v1/services/collector
    sg_weather_cs_hec_ingest_url = 'https://ingest.us-1.crowdstrike.com/api/ingest/hec/xxxxxx/v1/services/collector'
    sg_weather_cs_hec_api_key = 'xxxxxx'

    ##### Air Temperature across Singapore (https://beta.data.gov.sg/datasets/d_5b1a6d3688427dd41e2c234fe42fb863/view)
    sg_gov_data_base_url = 'https://api.data.gov.sg'
    sg_gov_air_temp_endpoint = '/v1/environment/air-temperature'

    loop_duration = 0
    sleep_duration = 5

    # init_envvar()
    # init_cli()

    if ((loop_duration > 0) and (sleep_duration > 0)):
      if (loop_duration < sleep_duration):
          error_message('Loop duration is shorter than sleep duration')
    elif (sleep_duration == 0):
        error_message('Sleep duration cannot be 0')

#######################################################################################################################
# main program
#######################################################################################################################

init_param()

old_ts = None
new_ts = None

sg_air_temp_hec = cs_hec_ingest_client(sg_weather_cs_hec_ingest_url, sg_weather_cs_hec_api_key)
sg_air_temp = sg_gov_data_client(sg_gov_data_base_url)

if (loop_duration == 0):
    i = True                                                                                                           # set to infinite loop
elif (loop_duration > 0):
    i = int(loop_duration / sleep_duration)                                                                            # determines number of times to loop

while(i):
    print('\nLoop: ' + str(i) + ' at ' + strftime('%H:%M:%S', time.localtime()))
    sg_air_temp_query_r = sg_air_temp.query(sg_gov_air_temp_endpoint)

    if (sg_air_temp_query_r.status_code == 200):
        api_health_status = sg_air_temp_query_r.json()["api_info"]["status"]

        if (api_health_status == 'healthy'):
            event_datetime = datetime.datetime.strptime(sg_air_temp_query_r.json()["items"][0]["timestamp"], '%Y-%m-%dT%H:%M:%S%z')        # convert string to datetime object
            new_ts = int(event_datetime.timestamp())                                                                   # in UTC timestamp format, but casted to int
            new_sg_air_temp_event_log = dict(IL_event_type = "SGAirTemp", evt_timestamp = new_ts)                      # dictionary object with timestamp as initial member

            if (new_ts != old_ts):                                                                                     # proceed only if it is new data from air temp API, else ignore
                # print('No. of stations: ' + str(len(r.json()["items"][0]["readings"])))                                # shows how many stations
                for station in sg_air_temp_query_r.json()["items"][0]["readings"]:                                     # get data for each weather station
                    sg_air_temp_event_log = new_sg_air_temp_event_log                                                  # prepare fresh event log for each station processed
                    sg_air_temp_event_log.update(station)                                                              # append station data to event log
                    sg_air_temp_event_log = '{"event": ' + json.dumps(sg_air_temp_event_log) + '}'                     # wrap the event data with "event", and convert dict's single quote to JSON double quote
                    sg_air_temp_hec_send_log_r = sg_air_temp_hec.send_log(sg_air_temp_event_log)
                    print(sg_air_temp_event_log)
                    print(sg_air_temp_hec_send_log_r.text)
                old_ts = new_ts

            # print(new_ts)
            # print(r.text)
            # print(len(r.json()["metadata"]["stations"]))
        else:
            error_message('API returned an status of: ' + api_health_status + '.\n')
    else:
        error_message('API returned an status of: ' + sg_air_temp_query_r.status_code + '.\n')

    if (loop_duration == 0):
        i = True
        print('Sleep forever loop... ' + str(sleep_duration))
        time.sleep(sleep_duration * 60)                                                                                # sleep infinite loop
    else:
        i -= 1

        if (i > 0):
            print('Sleep finite loop... ')
            time.sleep(sleep_duration * 60)                                                                            # sleep only if there if there are remaining iterations
        else:
            exit()                                                                                                     # else end
