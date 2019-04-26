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
from flask import Flask
from flask_restful import Resource, Api
import logging
import sys




log = logging.getLogger()
log.setLevel(logging.INFO)
formatter = logging.Formatter(fmt='%(asctime)s: %(levelname)s: %(lineno)d : %(message)s')
handler = logging.StreamHandler(stream=sys.stdout)
handler.setFormatter(formatter)
log.addHandler(handler)

class Pscrapper():
    def __init__(self):
        self.url_list = ['https://pastebin.com/u/ps66uk','https://pastebin.com/u/ExecuteMalware','https://pastebin.com/u/emf1123','https://pastebin.com/u/jroosen']
        #self.url_list = ['https://pastebin.com/u/jroosen']
        self.ioc_set = set()
        self.results_dict = defaultdict(dict)
        self.whitelist = r'(twitter|pastebin)'
        #place indicators in a set to reduce dups

    def is_hash(self,ioc):
        sha256_regex = r'(?=(\b[A-Fa-f0-9]{64}\b))'
        md5_regex = r'(?=(\b[A-Fa-f0-9]{32}\b))'
        if re.search(sha256_regex, ioc):
            return (True,"sha-256")
        elif re.search(md5_regex, ioc):
            return (True,"md5")
        else:
            return (False,False)

    def is_url(self, url):
        url_regex = r'^(h(tt|xx)p:\/\/www\.|h(tt|xx)ps:\/\/www\.|h(tt|xx)p:\/\/|h(tt|xx)ps:\/\/)([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}|(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(:[0-9]{1,5})?(\/.*)?$'
        if re.search(url_regex,url) == None:
            return False
        else:
            return True

    def crawl_page(self):
        date = datetime.today().strftime("%Y-%m-%d")
        date = '2019-04-25'
        for url in self.url_list:
            try:
                req = requests.get(url)
                if req.status_code == 200:
                    parse_html = BeautifulSoup(req.text, 'html.parser' )
                    links = parse_html.find_all('a',href=True)
                    for l in links:
                        match = re.search(r'emotet',l.text,re.I)
                        if match:
                            paste_date = re.search(r'[0-9]{4}(-|\/)?[0-9]{2}(-|\/)?[0-9]{2}', l.text)
                            #::this is done this way because dates come in diff formats.
                            if paste_date:
                                if paste_date:
                                    paste_date = paste_date.group()
                                    paste_date = re.sub(r'([0-9]{4})(-|\/)?([0-9]{2})(-|\/)?([0-9]{2})',r'\1-\3-\5', paste_date)
                                else:
                                    paste_date = date
                                if paste_date == date:
                                    paste_url = "https://pastebin.com/raw{}".format(l.get('href'))
                                    req = requests.get(paste_url)
                                    iocs =  [ioc for ioc in  req.text.split('\n')]
                                    [self.ioc_set.add(i)  for i in iocs if i]
                                    for ioc in self.ioc_set:
                                        ioc = ioc.rstrip()
                                        ishash = self.is_hash(ioc)
                                        if ishash[0] == True:
                                            self.results_dict[ioc].update({ishash[1]: ioc})
                                            self.results_dict[ioc].update(
                                                {'attributes': [{"name": "feed_id:emotet_pastebin_scraper", "value": True},
                                                                {"name": "pastebin:creation_time", "value": date}]})
                                            self.results_dict[ioc].update({"source": paste_url})
                                            self.results_dict[ioc].update({"tags": ['Emotet', url]})
                                        elif self.is_url(ioc) == True:
                                            whitelist = re.findall(self.whitelist,ioc)
                                            if whitelist: continue

                                            ioc = re.sub(r'h(tt|xx)ps?:\/\/','',ioc)
                                            self.results_dict[ioc].update({'url': ioc})
                                            self.results_dict[ioc].update(
                                                {'attributes': [{"name": "feed_id:emotet_pastebin_scrape", "value": True},
                                                                {"name": "pastebin:creation_time", "value": date}]})
                                            self.results_dict[ioc].update({"source": paste_url})
                                            self.results_dict[ioc].update({"tags": ['Emotet', url ]})
                            self.ioc_set.clear()
                else:
                    continue
            except requests.exceptions.RequestException as e:
                log.info(e)

        with open('emotet-analyzer.json', 'w') as fh:
            json.dump(self.results_dict, fh)

class Analyzer_api(Resource):

    def get(self):
        try:
            with open('emotet-analyzer.json', 'r') as fh:
                data = json.loads(fh.read())
                return data
        except:
            return {'error': 'unable to open ioc file'}

if __name__ == '__main__':
    #utc time

    scrapper = Pscrapper()
    scrapper.crawl_page()

    app = Flask(__name__)
    api = Api(app)
    api.add_resource(Analyzer_api,'/emotet_pastebin_scrapper')
    app.run(host='0.0.0.0', port=669, debug=True)




