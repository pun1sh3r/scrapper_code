'''
Emotet Pastebin scrapper.



This is a hackish code that aims to collect ioc's from pastebin accounts from well know researchers tracking emotet.

Output is placed in json format which is served in a flask api endpoint. This code is very experimental. Not suitable for prod environments. thanks to the following researchers for their contributions on emotet tracking:

* https://pastebin.com/u/ps66uk
* https://pastebin.com/u/ExecuteMalware
* https://pastebin.com/u/emf1123

'''
import json
import requests
from bs4 import BeautifulSoup
import re
from datetime import datetime
from pprint import pprint
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_restful import Resource, Api
import logging
import sys
import os

log = logging.getLogger()
log.setLevel(logging.ERROR)
formatter = logging.Formatter(fmt='%(asctime)s: %(levelname)s: %(filename)s : %(lineno)d : %(message)s')
handler = logging.FileHandler('/home/ubuntu/scrapper_engines/logs/feed.log')
handler.setFormatter(formatter)
log.addHandler(handler)


app = Flask(__name__)
api = Api(app)


class Pscrapper():
    def __init__(self):
        self.url_list = ['https://pastebin.com/u/ps66uk', 'https://pastebin.com/u/ExecuteMalware',
                         'https://pastebin.com/u/emf1123', 'https://pastebin.com/u/jroosen']
        self.ioc_set = set()
        self.results_dict = defaultdict(dict)
        self.whitelist = r'(twitter|pastebin)'

    def is_hash(self, ioc):
        sha256_regex = r'(?=(\b[A-Fa-f0-9]{64}\b))'
        md5_regex = r'(?=(\b[A-Fa-f0-9]{32}\b))'
        if re.search(sha256_regex, ioc):
            return (True, "sha-256")
        elif re.search(md5_regex, ioc):
            return (True, "md5")
        else:
            return (False, False)

    def is_url(self, url):
        url_regex = r'^(h(tt|xx)p:\/\/www\.|h(tt|xx)ps:\/\/www\.|h(tt|xx)p:\/\/|h(tt|xx)ps:\/\/)([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}|(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(:[0-9]{1,5})?(\/.*)?$'
        if re.search(url_regex, url) == None:
            return False
        else:
            return True

    def crawl_page(self):
        date = datetime.today().strftime("%Y-%m-%d")
        for url in self.url_list:
            try:
                req = requests.get(url)
                if req.status_code == 200:
                    parse_html = BeautifulSoup(req.text, 'html.parser')
                    links = parse_html.find_all('a', href=True)
                    for l in links:
                        match = re.search(r'emotet', l.text, re.I)
                        if match:
                            paste_date = re.search(r'[0-9]{4}(-|\/)?[0-9]{2}(-|\/)?[0-9]{2}', l.text)
                            #::this is done this way because dates come in diff formats.
                            if paste_date:
                                if paste_date:
                                    paste_date = paste_date.group()
                                    paste_date = re.sub(r'([0-9]{4})(-|\/)?([0-9]{2})(-|\/)?([0-9]{2})', r'\1-\3-\5',
                                                        paste_date)
                                else:
                                    paste_date = date
                                if paste_date == date:
                                    paste_url = "https://pastebin.com/raw{}".format(l.get('href'))
                                    req = requests.get(paste_url)
                                    iocs = [ioc for ioc in req.text.split('\n')]
                                    [self.ioc_set.add(i) for i in iocs if i]
                                    for ioc in self.ioc_set:
                                        ioc = ioc.rstrip()
                                        ishash = self.is_hash(ioc)
                                        if ishash[0] == True:
                                            self.results_dict[ioc].update({ishash[1]: ioc})
                                            self.results_dict[ioc].update(
                                                {'attributes': [
                                                    {"name": "trt:threat_scraper", "value": "emotet_pastebin_scraper" },
                                                    {"name": "pastebin:creation_time", "value": date},
                                                    {"name": "trt:malware_name", "value" : 'Emotet' },
                                                    {"name": "pastebin:source_url" , "value" : paste_url}]})
                                            self.results_dict[ioc].update({"source": url})
                                        elif self.is_url(ioc) == True:
                                            whitelist = re.findall(self.whitelist, ioc)
                                            if whitelist: continue
                                            ioc = re.sub(r'h(tt|xx)ps?:\/\/', '', ioc)
                                            self.results_dict[ioc].update({'url': ioc})
                                            self.results_dict[ioc].update(
                                                {'attributes': [
                                                    {"name": "trt:threat_scraper", "value": "emotet_pastebin_scraper" },
                                                    {"name": "pastebin:creation_time", "value": date},
                                                    {"name": "trt:malware_name", "value": 'Emotet'},
                                                    {"name": "pastebin:source_url", "value": paste_url}]}
                                            )
                                            self.results_dict[ioc].update({"source": url})
                            self.ioc_set.clear()
                else:
                    continue
            except requests.exceptions.RequestException as e:
                log.error(e)

        with open('emotet-analyzer.json', 'w') as fh:
            json.dump(self.results_dict, fh)


@app.route('/emotet_pastebin_scrapper',methods=["GET"])
def emotet_api():
    scraper = Pscrapper()
    scraper.crawl_page()
    try:
        path = os.getcwd() + '/emotet-analyzer.json'
        exist = os.path.isfile(path)
        if exist:
            with open(path, 'r') as fh:
                data = json.loads(fh.read())
                return jsonify(data)
    except:
        log.error('error unable to open ioc file')
        return jsonify({'Error': 'file might not be available. file is populated around 10 PM EST'}   )

@app.route('/urlhaus_scraper',methods=["GET"])
def urlhaus_api():
    path = os.getcwd() + '/urlhaus_analyzer.json'
    exist = os.path.isfile(path)
    if exist:
        with open(path,'r') as fh:
            data = fh.read()
            data = json.loads(data)
        return jsonify(data)
    else:
        log.error('error unable to open ioc file')
        return jsonify({'Error': 'file might not be available. file is populated around 10 PM EST'})

@app.route('/phishstats_scraper',methods=["GET"])
def phishstats_api():
    path = os.getcwd() + '/phishstats_analyzer.json'
    exist = os.path.isfile(path)
    if exist:
        with open(path,'r') as fh:
            data = fh.read()
            data = json.loads(data)
        return jsonify(data)
    else:
        log.error('error unable to open ioc file')
        return jsonify({'Error': 'file might not be available. file is populated around 10 PM EST'})
#if __name__ == '__main__':
#    flask_app.run(host='127.0.0.1')