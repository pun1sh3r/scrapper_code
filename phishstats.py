import json
import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime, timedelta
from pprint import pprint
from collections import defaultdict
from flask import Flask, request, jsonify
import logging
import logging.handlers
import sys
import os
from collections import defaultdict
import csv
from pprint import pprint


log = logging.getLogger()
log.setLevel(logging.ERROR)
formatter = logging.Formatter(fmt='%(asctime)s: %(levelname)s: %(filename)s:  %(lineno)d : %(message)s')
handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)
log.addHandler(handler)



class phishstats():
    def __init__(self):
        self.url = 'https://phishstats.info/phish_score.txt'
        self.results_dict = defaultdict(dict)

    def crawl_page(self):
        os.chdir(sys.path[0])
        outfile = sys.path[0] + '/phishstats_analyzer.json'
        date = datetime.today() - timedelta(days=1)
        date = date.strftime("%d-%m-%y")
        #date = '12-06-19'
        try:
            req = requests.get(self.url)
            data = req.text
            data = data.split('\n')
            regex = re.compile(r'{}.*'.format(date))
            matched_rows = list(filter(regex.search,data))
            csv_reader = csv.reader(matched_rows)
            for row in csv_reader:
                first_seen = row[0]
                phish_score = row[1]
                phish_url = row[2]
                self.results_dict[phish_url].update({'url' : phish_url})
                self.results_dict[phish_url].update({'source' : 'phishstats.info'})
                self.results_dict[phish_url].update({'attributes': [
                    {'name': 'trt:threat_scraper', 'value': 'phishstats_scraper'},
                    {'name' : 'phishstats:score', 'value' : phish_score},
                    {'name' : 'phishstats:firstseen', 'value': first_seen},

                ]})
            with open('phishstats_analyzer.json','w') as fh:

                json.dump(self.results_dict,fh)
        except requests.exceptions.RequestException as e:
            log.error(e)
            return 0

if __name__ == '__main__':
    obj = phishstats()
    obj.crawl_page()

