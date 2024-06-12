#######################################################################################################################
#######################################################################################################################
#
# Packages to install:
# - "pip install httpx[http2]" (Install httpx with HTTP/2 support)
#
# Usage:
#  - Key parameters are:
#    - cs_sg_air_temp_hec_url -- CrowdStrike SG air temperature HEC ingestion URL
#    - cs_sg_air_temp_hec_api_key -- CrowdStrike SG air temperature HEC API key
#    - sg_gov_data_base_url -- SG government data access API base URL
#    - sg_gov_air_temp_endpoint -- SG air temperature API endpoint
#    - loop_duration -- Duration to run (in minutes)
#    - sleep_duration -- Duration to sleep in between API calls (in minutes)
#  - These parameters can be initialized from:
#    - environment variables (if they exists):
#      - CS_SG_AIR_TEMP_HEC_URL
#      - CS_SG_AIR_TEMP_HEC_API_KEY
#      - SG_GOV_DATA_BASE_URL
#      - SG_GOV_AIR_TEMP_ENDPOINT
#      - LOOP_DURATION
#      - SLEEP_DURATION
#    - key-value pair in a text configuration file (specified via commandline using argument "--configfile") with the
#      following keys:
#      - CS_SG_AIR_TEMP_HEC_URL
#      - CS_SG_AIR_TEMP_HEC_API_KEY
#      - SG_GOV_DATA_BASE_URL
#      - SG_GOV_AIR_TEMP_ENDPOINT
#      - LOOP_DURATION
#      - SLEEP_DURATION
#    - commandline arguments
#      - "--cs_sg_air_temp_hec_url"
#      - "--cs_sg_air_temp_hec_api_key"
#      - "--sg_gov_data_base_url"
#      - "--sg_gov_air_temp_endpoint"
#      - "--loop_duration"
#      - "--sleep_duration"
#
# Example:
#
#           sg_air_temp_hec.py --configfile config.txt
#
#    The configuration file "config.txt" contains the necessary parameters needed for this script to work.
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
cs_sg_air_temp_hec_url = None
cs_sg_air_temp_hec_api_key = None

##### SG govt data source
sg_gov_data_base_url = None
sg_gov_data_api_endpoint = None

##### Loop & sleep control
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
    global cs_sg_air_temp_hec_url
    global cs_sg_air_temp_hec_api_key

    global sg_gov_data_base_url
    global sg_gov_air_temp_endpoint

    global loop_duration
    global sleep_duration

    cs_sg_air_temp_hec_url = os.environ.get('CS_SG_AIR_TEMP_HEC_URL')
    cs_sg_air_temp_hec_api_key = os.environ.get('CS_SG_AIR_TEMP_HEC_API_KEY')

    sg_gov_data_base_url = os.environ.get('SG_GOV_DATA_BASE_URL')
    sg_gov_air_temp_endpoint = os.environ.get('SG_GOV_AIR_TEMP_ENDPOINT')

    loop_duration = os.environ.get('LOOP_DURATION')
    sleep_duration = os.environ.get('SLEEP_DURATION')

def init_configfile(config_file):
    global cs_sg_air_temp_hec_url
    global cs_sg_air_temp_hec_api_key

    global sg_gov_data_base_url
    global sg_gov_air_temp_endpoint

    global loop_duration
    global sleep_duration

    dummy = ' '
    try:
        with open(config_file) as f:                                                                                   # ConfigParser needs a [section] structure, otherwise it is not happy
            file_content = '[' + dummy +']\n' + f.read()
    except Exception as ex:
       error_message(config_file + ' :', exception = ex)

    config = configparser.RawConfigParser()
    config.read_string(file_content)

    try:
        cs_sg_air_temp_hec_url = config[dummy]['CS_SG_AIR_TEMP_HEC_URL']
        cs_sg_air_temp_hec_api_key = config[dummy]['CS_SG_AIR_TEMP_HEC_API_KEY']

        sg_gov_data_base_url = config[dummy]['SG_GOV_DATA_BASE_URL']
        sg_gov_air_temp_endpoint = config[dummy]['SG_GOV_AIR_TEMP_ENDPOINT']

        loop_duration = config[dummy]['LOOP_DURATION']
        sleep_duration = config[dummy]['SLEEP_DURATION']
    except Exception as ex:
        error_message(config_file + ' :', exception = ex)

def init_cli():
    global cs_sg_air_temp_hec_url
    global cs_sg_air_temp_hec_api_key

    global sg_gov_data_base_url
    global sg_gov_air_temp_endpoint

    global loop_duration
    global sleep_duration

    # parse CLI
    parser = argparse.ArgumentParser()

    ##### generic use -- config file
    parser.add_argument('--configfile', help = 'configuration file')

    ##### CrowdStrike HEC
    parser.add_argument('--cs_sg_air_temp_hec_url', help = 'CrowdStrike SG air temperature HEC ingestion URL')
    parser.add_argument('--cs_sg_air_temp_hec_api_key', help = 'CrowdStrike SG air temperature HEC API key')

    ##### SG air temperature data
    parser.add_argument('--sg_gov_data_base_url', help = 'SG government data access API base URL')
    parser.add_argument('--sg_gov_air_temp_endpoint', help = 'SG air temperature API endpoint')

    ##### Loop & sleep control
    parser.add_argument('--loop_duration', help = 'Duration to run (in minutes)')
    parser.add_argument('--sleep_duration', help = 'Duration to sleep in between API calls (in minutes)')

    args = parser.parse_args()

    if args.configfile is not None:
        init_configfile(args.configfile)

    if args.cs_sg_air_temp_hec_url is not None:
        cs_sg_air_temp_hec_url = args.cs_sg_air_temp_hec_url
    if args.cs_sg_air_temp_hec_api_key is not None:
        cs_sg_air_temp_hec_api_key = args.cs_sg_air_temp_hec_api_key

    if args.sg_gov_data_base_url is not None:
        sg_gov_data_base_url = args.sg_gov_data_base_url
    if args.sg_gov_air_temp_endpoint is not None:
        sg_gov_air_temp_endpoint = args.sg_gov_air_temp_endpoint

    if args.loop_duration is not None:
        loop_duration = args.loop_duration
    if args.sleep_duration is not None:
        sleep_duration = args.sleep_duration

    if not ((has_value(cs_sg_air_temp_hec_url)) and (has_value(cs_sg_air_temp_hec_api_key)) and (has_value(sg_gov_data_base_url)) and (has_value(sg_gov_air_temp_endpoint)) and (has_value(loop_duration)) and (has_value(sleep_duration))):
        error_message('Insufficient arguments to proceed.\n')

def init_param():
    global loop_duration
    global sleep_duration

    init_envvar()
    init_cli()

    if (loop_duration != None):
        loop_duration = int(loop_duration)
    if (sleep_duration != None):
        sleep_duration = int(sleep_duration)

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

sg_air_temp_hec = cs_hec_ingest_client(cs_sg_air_temp_hec_url, cs_sg_air_temp_hec_api_key)
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
