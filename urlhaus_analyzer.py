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
import json
from multiprocessing import Lock, Process, Queue, current_process


log = logging.getLogger()
log.setLevel(logging.ERROR)
formatter = logging.Formatter(fmt='%(asctime)s: %(levelname)s: %(filename)s:  %(lineno)d : %(message)s')
handler = logging.StreamHandler(stream=sys.stdout)
handler = logging.FileHandler()
handler.setFormatter(formatter)
log.addHandler(handler)


class Urlhaus():

    def __init__(self):
        self.url = 'https://urlhaus.abuse.ch/downloads/csv/'
        self.results_dict = defaultdict(dict)
        self.api = 'https://urlhaus-api.abuse.ch/v1/url/'

    def query_url(self,ioc):
        #; link example with no payloads http://refugeetents.co.za/wp-content/If1/ify.doc
        #; with payload 'http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/
        #ioc = 'http://refugeetents.co.za/wp-content/If1/ify.doc'
        #ioc = 'http://sskymedia.com/VMYB-ht_JAQo-gi/INV/99401FORPO/20673114777/US/Outstanding-Invoices/'
        #:this one is giving json errors http://terryhill.top/invoice/tkcrypt.exe
        data = {'url': ioc}
        log.debug('Crawling url: {}'.format(ioc))
        try:
            req = requests.post(self.api, data=data)
            try:
                resp = req.json()
                self.results_dict[ioc].update({'url': ioc})
                if resp['tags']:
                    tags = ','.join(resp['tags'])
                else:
                    tags ='null'

                self.results_dict[ioc].update({'attributes' : [
                    {'name' : 'trt:threat_scraper', "value": 'urlhaus_scraper'},
                    {'name': 'urlhaus:url_status', 'value': resp['url_status']},
                    {'name': 'urlhaus:urlhaus_reference', 'value': resp['urlhaus_reference']},
                    {'name': 'urlhaus:threat', 'value': resp['threat']},
                    {'name': 'urlhaus:date_added', 'value': resp['date_added']},
                    {'name': 'urlhaus:reporter', 'value': resp['reporter']},
                    {'name': 'urlhaus:tags', 'value': tags },
                ],
                    })
                if resp['payloads']:
                    for p in resp['payloads']:
                        self.results_dict[ioc].update({p['response_md5']: {'attributes': [{'name': 'urlhaus:association' , 'value' :ioc }]} })
                        self.results_dict[ioc].update(
                            {p['response_sha256']: {'attributes': [{'name': 'urlhaus:association', 'value': ioc}]}})

                        self.results_dict[p['response_md5']].update({'md5' : p['response_md5'] })
                        self.results_dict[p['response_md5']].update({'attributes': [
                            {'name': 'urlhaus:urlhaus_filename', 'value': p['filename']},
                            {'name': 'urlhaus:urlhaul_sha256', 'value' : p['response_sha256']},
                            {'name':'urlhaus:urlhaus_firstseen', 'value' : p['firstseen']}
                        ]})

                        if p['virustotal'] == None:
                            self.results_dict[p['response_md5']]['attributes'].append({'name': 'urlhaus:urlhaus_virustotal', 'value' : 'null'})
                        else:
                            self.results_dict[p['response_md5']]['attributes'].append({'name': 'urlhaus:urlhaus_virustotal', 'value' : p['virustotal']['percent']})

                return self.results_dict
            except Exception as ex :
                log.error("json exception on {} {}".format(ex, ioc))
        except requests.exceptions.RequestException as e:
            log.error(e)
            return 0

    def worker(self,work_queue,done_queue,url_queue):
        try:

            for url in iter(work_queue.get, 'STOP'):
                try:
                    data = self.query_url(url)
                    log.debug("%s - %s " % (current_process().name, url))
                    url_queue.put(data)
                except Exception as ex:
                    continue
        except Exception as  e:
            done_queue.put("%s failed on %s with: %s" % (current_process().name, url, e.message))
        return True

    def crawl_page(self):
        os.chdir(sys.path[0])
        outfile = sys.path[0] + '/urlhaus_analyzer.json'

        date = datetime.today() - timedelta(days=1)
        date = date.strftime("%Y-%m-%d")
        try:
            req = requests.get(self.url)
            data = req.text
            data = data.split('\n')
            regex = re.compile(r'{}.*'.format(date))
            matched_rows = list(filter(regex.search,data))
            if matched_rows:
                del matched_rows[0]
                chunks = [matched_rows[i:i+20] for i in range(0,len(matched_rows),20)]
                work_queue = Queue()
                processes = list()
                done_queue = Queue()
                url_queue = Queue()
                result_set = list()
                for chunk in chunks:
                    urls = [work_queue.put(url.split('","')[2]) for url in chunk]
                    workers = 30
                    for w in range(workers):
                        p = Process(target=self.worker, args=(work_queue,done_queue ,url_queue))
                        p.start()
                        processes.append(p)
                        work_queue.put('STOP')
                    for p in processes:
                        p.join(1)
                    url_queue.put("STOP")
                    for i in iter(url_queue.get,'STOP'):
                        if i is None or i == 0:
                            continue
                        result_set.append(i)
                with open('urlhaus_analyzer.json', 'w') as fh:
                    json.dump(result_set,fh)
        except requests.exceptions.RequestException as e:
            log.error(e)
            return 0


if __name__ == '__main__':
    obj = Urlhaus()
    log.debug('Crawling urlhaus started...')
    obj.crawl_page()
    log.debug("Crawling urlhaus completed... ")




