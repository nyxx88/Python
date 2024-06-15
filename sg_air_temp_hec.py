#######################################################################################################################
#######################################################################################################################
#
# Packages to install:
# - "pip install httpx[http2]" (Install httpx with HTTP/2 support)
#
# Usage:
#  - Key parameters are:
#    - cs_hec_url -- CrowdStrike SG air temperature HEC ingestion URL
#    - cs_hec_api_key -- CrowdStrike SG air temperature HEC API key
#    - sg_gov_air_temp_endpoint -- SG air temperature API endpoint
#    - loop_duration -- Duration to run (in minutes)
#    - sleep_duration -- Duration to sleep in between API calls (in minutes)
#  - These parameters can be initialized from:
#    - environment variables (if they exists):
#      - CS_HEC_URL
#      - CS_HEC_API_KEY
#      - SG_GOV_AIR_TEMP_ENDPOINT
#      - LOOP_DURATION
#      - SLEEP_DURATION
#    - key-value pair in a text configuration file (specified via commandline using argument "--configfile") with the
#      following keys:
#      - CS_HEC_URL
#      - CS_HEC_API_KEY
#      - SG_GOV_AIR_TEMP_ENDPOINT
#      - LOOP_DURATION
#      - SLEEP_DURATION
#    - commandline arguments
#      - "--cs_hec_url"
#      - "--cs_hec_api_key"
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
cs_hec_url = None
cs_hec_api_key = None

##### SG govt data source
sg_gov_data_api_endpoint = None

##### Loop & sleep control
loop_duration = None                                                                                                                       # in minutes
sleep_duration = None                                                                                                                      # in minutes

#######################################################################################################################
# classes
#######################################################################################################################

class cs_hec_ingest_client:
    http_client = httpx.Client(http2=True)

    def __init__(self, ingest_url, api_key):
        self.ingest_url = ingest_url
        self.api_key = api_key
        self.total_header_sent = 0
        self.total_data_sent = 0

        self.header = {"Content-Type": "text/plain; charset=utf-8"}
        self.header.update({"authorization" : "bearer " + self.api_key})

    def send_log(self, *log_elements):
        log_json = {}                                                                                                                      # cat into a dictionary, which will be converted to a JSON string later

        for log_element in log_elements:
            log_json.update(log_element)                                                                                                   # append individual log elements into log JSON object
        log_str = json.dumps(log_json)
        self.total_header_sent += len(self.header)
        self.total_data_sent += len(log_str)
        print(log_str)
        # return(True)
        return(self.http_client.post(self.ingest_url, headers = self.header, data = log_str))

class sg_air_temp_client:
    http_client = httpx.Client(http2=True)

    def __init__(self, endpoint_url):
        self.endpoint_url = endpoint_url
        self.header = {"accept": "*/*"}
        self.station_r = station_response()

    def get_station_readings(self):
        r = self.http_client.get(self.endpoint_url, headers = self.header)

        self.station_r.status_code = r.status_code                                                                                         # return HTTP status code regardless
        if (r.status_code == 200):
            api_health_status = r.json()["api_info"]["status"]
            if (api_health_status == 'healthy'):
                self.station_r.status = True
                self.station_r.msg = 'OK'

                # self.station_r.timestamp = r.json()["items"][0]["timestamp"]
                self.station_r.timestamp = datetime.datetime.strptime(r.json()["items"][0]["timestamp"], '%Y-%m-%dT%H:%M:%S%z')            # convert string to datetime object
                self.station_r.tz = tz = self.station_r.timestamp.strftime('%z')
                self.station_r.station_results = r.json()["items"][0]["readings"]
                self.station_r.station_count = len(self.station_r.station_results)
            else:
                self.station_r.status = False
                self.station_r.msg = 'API returned health: ' + api_health_status
                self.station_r.timestamp = None
                self.station_r.tz = None
                self.station_r.station_results = None
                self.station_r.station_count = None
        else:
            self.station_r.status = False
            self.station_r.msg = 'API returned HTTP status: ' + str(r.status_code)
            self.station_r.timestamp = None
            self.station_r.tz = None
            self.station_r.station_results = None
            self.station_r.station_count = None

        return(self.station_r)

class station_response:
    status = None
    msg = None
    timestamp = None
    tz = None
    station_count = None
    station_results = None

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
    global cs_hec_url
    global cs_hec_api_key

    global sg_gov_air_temp_endpoint

    global loop_duration
    global sleep_duration

    cs_hec_url = os.environ.get('CS_HEC_URL')
    cs_hec_api_key = os.environ.get('CS_HEC_API_KEY')

    sg_gov_air_temp_endpoint = os.environ.get('SG_GOV_AIR_TEMP_ENDPOINT')

    loop_duration = os.environ.get('LOOP_DURATION')
    sleep_duration = os.environ.get('SLEEP_DURATION')

def init_configfile(config_file):
    global cs_hec_url
    global cs_hec_api_key

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
        cs_hec_url = config[dummy]['CS_HEC_URL']
        cs_hec_api_key = config[dummy]['CS_HEC_API_KEY']

        sg_gov_air_temp_endpoint = config[dummy]['SG_GOV_AIR_TEMP_ENDPOINT']

        loop_duration = config[dummy]['LOOP_DURATION']
        sleep_duration = config[dummy]['SLEEP_DURATION']
    except Exception as ex:
        error_message(config_file + ' :', exception = ex)

def init_cli():
    global cs_hec_url
    global cs_hec_api_key

    global sg_gov_data_base_url
    global sg_gov_air_temp_endpoint

    global loop_duration
    global sleep_duration

    # parse CLI
    parser = argparse.ArgumentParser()

    ##### generic use -- config file
    parser.add_argument('--configfile', help = 'configuration file')

    ##### CrowdStrike HEC
    parser.add_argument('--cs_hec_url', help = 'CrowdStrike SG air temperature HEC ingestion URL')
    parser.add_argument('--cs_hec_api_key', help = 'CrowdStrike SG air temperature HEC API key')

    ##### SG air temperature data
    parser.add_argument('--sg_gov_air_temp_endpoint', help = 'SG air temperature API endpoint')

    ##### Loop & sleep control
    parser.add_argument('--loop_duration', help = 'Duration to run (in minutes)')
    parser.add_argument('--sleep_duration', help = 'Duration to sleep in between API calls (in minutes)')

    args = parser.parse_args()

    if args.configfile is not None:
        init_configfile(args.configfile)

    if args.cs_hec_url is not None:
        cs_hec_url = args.cs_hec_url
    if args.cs_hec_api_key is not None:
        cs_hec_api_key = args.cs_hec_api_key

    if args.sg_gov_air_temp_endpoint is not None:
        sg_gov_air_temp_endpoint = args.sg_gov_air_temp_endpoint

    if args.loop_duration is not None:
        loop_duration = args.loop_duration
    if args.sleep_duration is not None:
        sleep_duration = args.sleep_duration

    if not ((has_value(cs_hec_url)) and (has_value(cs_hec_api_key)) and (has_value(sg_gov_air_temp_endpoint)) and (has_value(loop_duration)) and (has_value(sleep_duration))):
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

sg_air_temp_hec = cs_hec_ingest_client(cs_hec_url, cs_hec_api_key)
sg_air_temp_source = sg_air_temp_client(sg_gov_air_temp_endpoint)

# station_r = sg_air_temp_source.get_station_readings()
# print(station_r.evt_timestamp)
# exit()

if (loop_duration == 0):
    i = True                                                                                                                               # set to infinite loop
elif (loop_duration > 0):
    i = int(loop_duration / sleep_duration)                                                                                                # determines number of times to loop

while(i):
    print('\nLoop: ' + str(i) + ' at ' + strftime('%H:%M:%S', time.localtime()))
    station_r = sg_air_temp_source.get_station_readings()                                                                                  # call API to get current air temp readings

    if (station_r.status == True):                                                                                                         # if API call was successful & API status is healthy
        new_ts = int(station_r.timestamp.timestamp()) * 1000                                                                               # convert datetime object into UTC timestamp format, then cast into int. LogScale expects 13 digit Epoch time
        new_sg_air_temp_event_log = dict(IL_event_type = "SGAirTemp", evt_timestamp = new_ts)                                              # new dictionary object (to hold log details) with static fields as initial members

        if (new_ts != old_ts):                                                                                                             # proceed only if it is new data from air temp API, else ignore
            # print('No. of stations: ' + str(station_r.station_count))                                                                      # shows how many stations
            for station in station_r.station_results:                                                                                      # get data for each weather station
                sg_air_temp_event_log = new_sg_air_temp_event_log                                                                          # prepare fresh event log for each station processed
                sg_air_temp_event_log.update(station)                                                                                      # append station data to event log
                hec_r = sg_air_temp_hec.send_log(dict(event = sg_air_temp_event_log), dict(time = new_ts), dict(timezone = station_r.tz))
                print(hec_r.text)
            old_ts = new_ts
    else:
        error_message(station_r.msg + '.\n')

    if (loop_duration == 0):
        i = True
        print('Infinite loop sleep... ' + str(sleep_duration))
        time.sleep(sleep_duration * 60)                                                                                # sleep infinite loop
    else:
        i -= 1

        if (i > 0):
            print('Finite loop sleep... ')
            time.sleep(sleep_duration * 60)                                                                            # sleep only if there if there are remaining iterations
        else:
            exit()                                                                                                     # else end
