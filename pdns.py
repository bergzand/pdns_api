# Copyright 2016 - Koen Zandberg
#
# Licensed under the EUPL, Version 1.1 or -- as soon they will be approved by
# the European Commission -- subsequent versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the Licence is distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
#

import requests
import logging
from collections import Counter

class Client(object):

    def __init__(self,
                 host='localhost',
                 port=8081,
                 key='secret',
                 ):
        self.logger = logging.getLogger('pdns')
        self.host = host
        self.port = port
        self.key = key

        self.url = 'http://{}:{}'.format(self.host, self.port)

        self.headers = {
            'user-agent': 'python-pdns-api/0',
            'pragma': 'no-cache',
            'cache-control': 'no-cache',
            'X-API-KEY': self.key
        }
        # Do server and api discovery
        self._discover_version()

    def servers(self):
        if self.version == 'exp':
            url = '/servers'
        elif self.version == '1':
            url = '/api/v1/servers'
        server_data = self.get(url)
        servers = []
        for server in server_data:
            new_server = Server(
                server['type'],
                server['id'],
                server['url'],
                server['daemon_type'],
                server['version'],
                server['config_url'],
                server['zones_url'],
                self
            )
            servers.append(new_server)
        return servers

    def _discover_version(self):
        url = self.url + '/api'
        r = requests.get(url, headers=self.headers)
        if r.status_code == requests.codes.ok:
            # Todo: version endpoint discovery
            self.version = '1'
        elif r.status_code == requests.codes.not_found:
            # Experimental version (auth v3.4.x)
            self.version = 'exp'

    def _build_url(self, url):
        if not url.startswith('/'):
            url = '/' + url
        return self.url + url

    def get(self, url, json=True):
        full_url = self._build_url(url)
        print full_url
        r = requests.get(full_url, headers=self.headers)
        if r.status_code not in (200, 400, 422):
            r.raise_for_status()
        return r.json() if json else r.content

    def post(self, url, content):
        full_url = self._build_url(url)
        r = requests.post(full_url, json=content, headers=self.headers)
        if r.status_code not in (200, 400, 422):
            r.raise_for_status()
        self.logger.info(r.content)
        return r.json()

    def patch(self, url, content):
        full_url = self._build_url(url)
        r = requests.patch(full_url, json=content, headers=self.headers)
        if r.status_code not in (200, 400, 422):
            r.raise_for_status()
        self.logger.info(r.content)

    def put(self, url, content):
        full_url = self._build_url(url)
        r = requests.post(full_url, json=content, headers=self.headers)
        if r.status_code not in (200, 400, 422):
            r.raise_for_status()
        self.logger.info(r.content)

    def delete(self, url):
        full_url = self._build_url(url)
        r = requests.delete(full_url, headers=self.headers)
        if r.status_code not in (200, 400, 422):
            r.raise_for_status()

    def get_version(self):
        return self.version


class Server(object):
    def __init__(self,
                 type,
                 name,
                 url,
                 daemon_type,
                 version,
                 config_url,
                 zones_url,
                 client
                 ):
        self.type = type
        self.name = name
        self.url = url
        self.daemon_type = daemon_type
        self.version = version
        self.config_url = config_url.split('{', 1)[0]
        self.zones_url = zones_url.split('{', 1)[0]
        self.client = client
        self._zones = []
        self.logger = logging.getLogger('pdns.server-{}'.format(self.name))
        self.refresh()

    def zones(self):
        return self._zones

    def config(self, setting=None):
        options = []
        if setting:
            url = self.config_url + '/' + setting
            options.append(self.client.get(url))
        else:
            options = self.client.get(self.config_url)
        return options

    def refresh(self):
        data = self.client.get(self.url)
        # todo: update self (Implement this shit)
        zd = self.client.get(self.zones_url)
        for zone in zd:
            new_zone = Zone(zone['name'],
                            zone['kind'].lower(),
                            zone['masters'],
                            None,
                            zone['serial'],
                            zone['dnssec'],
                            zone['url'],
                            client=self.client
                            )
            self._zones.append(new_zone)

    def add_zone(self, zone):
        exists = False
        for cur_zone in self._zones:
            if zone.name == cur_zone.name:
                exists = True
        if exists:
            raise pdnsZoneExists(cur_zone.name)
        data = zone.dict()
        zd = self.client.post(self.zones_url, data)
        #todo api version check
        zone.update(
            url=zd['url'],
        )
        self._zones.append(zone)

    def del_zone(self, zone_id):
        for zone in self._zones:
            if zone.name == zone_id:
                self._zones.remove(zone)
                self.client.delete(zone.url)

class Zone(object):
    def __init__(self,
                 name,
                 kind,
                 masters=None,
                 nameservers=None,
                 serial=None,
                 dnssec=False,
                 url=None,
                 client=None
                 ):
        self.name = name
        self.identifier = name
        self.type = type
        self.kind = kind
        self.serial = serial if serial else 0
        self.masters = masters if masters else []
        self.nameservers = nameservers if nameservers else []

        self.url = url if url else None
        self.dnssec = dnssec
        self.soa_edit = None
        self.soa_edit_api = None

        self._newlist = []
        self._patchlist = []
        self._dellist = []
        self._client = client
        self.refresh()

    def dict(self):
        """
        Returns a dictionary representation of the zone
        """
        data = {
            'name': self.name,
            'id': self.name,
            'kind': self.kind
        }

        if self.kind == 'native':
            data['nameservers'] = self.nameservers
        elif self.kind == 'slave':
            data['masters'] = self.masters
        return data

    def update(self,
               url=None,
               ):
        if url:
            self.url = url

    def refresh(self):
        data = self._client.get(self.url)
        self.name = data['name']
        self.dnssec = data['dnssec']
        self.identifier = data['id']
        self.kind = data['kind']
        self.last_check = data['last_check']
        self.notified_serial = data['notified_serial']
        self.account = data['account']
        self.serial = data['serial']
        self.soa_edit = data['soa_edit']
        self.soa_edit_api = data['soa_edit_api']

    def rrsets(self):
        version = self._client.get_version()
        rrsets = []
        if version == 'exp':
            rrsets = self._client.get(self.url)['records']
        elif version == '1':
            rrsets = self._client.get(self.url)['rrsets']
        for rrset in rrsets:
            new_rrset = RRset(rrset['name'],
                              rrset['type'],
                              rrset['ttl'] if 'ttl' in rrset else None,
                              rrset['records'],
                              rrset['comments']
                              )
            new_rrset._reg_zone(self)
            yield new_rrset

    def commit(self):
        final_list = []
        new_list = []
        for rrset in self._newlist:
            d_rrset = rrset.dict(self._client.get_version())
            new_list.append(d_rrset)
        patch_list = []
        for rrset in self._patchlist:
            d_rrset = rrset.dict(self._client.get_version())
            d_rrset['changetype'] = 'REPLACE'
            patch_list.append(d_rrset)
        del_list = []
        for rrset in self._dellist:
            d_rrset = rrset.dict(self._client.get_version())
            d_rrset['records'] = []
            d_rrset['comments'] = []
            d_rrset['changetype'] = 'DELETE'
            del_list.append(d_rrset)
            self._rrsets.remove(rrset)
        final_list.extend(patch_list)
        final_list.extend(del_list)
        final_list.extend(new_list)
        data = {"rrsets": final_list}
        if self._client and len(final_list):
            self._client.patch(self.url, data)
        self._patchlist = []
        self._dellist = []
        self._newlist = []

    def notify(self):
        self._client.put(self.url + '/notify')

    def retrieve(self):
        self._client.put(self.url + '/axfr-retrieve')

    def export(self):
        """
        Return the zone in AXFR format. Not recommended for parsing.
        :return: AXFR of the zone as multiline string
        """
        return self._client.get(self.url + '/export', json=False)

    def _record_changed(self, rrset):
        self._patchlist.append(rrset)

    def _record_deleted(self, rrset):
        self._dellist.append(rrset)


class Metadata(object):
    pass


class RRset(object):
    def __init__(self,
                 name,
                 type,
                 ttl=None,
                 records=None,
                 comments=None):
        self.name = name
        self.type = type
        self.ttl = ttl if ttl else records[0]['ttl']
        self._records = records if records else []
        self._comments = comments if comments else []
        self._zone = None

    def dict(self, version='1'):
        data = {
            'name': self.name,
            'type': self.type,
        }
        if version == 'exp':
            data['records'] = [{'content': r['content'],
                                'name': self.name,
                                'ttl': self.ttl,
                                'type': self.type,
                                'disabled': r['disabled'],
                                } for r in self._records]
        elif version == '1':
            data['ttl'] = self.ttl
            data['records'] = [{'content': r['content'],
                               'disabled': r['disabled']
                               } for r in self._records ]
        return data

    def add_records(self, records):
        if type(records) == list:
            self._records.extend(records)
        else:
            self._records.append(records)
        self._notify_zone()


    def del_records(self, records):
        if type(records) == list:
            for record in records:
                self._records.remove(record)
        else:
            self._records.remove(records)
        self._notify_zone()

    def add_comments(self, comments):
        pass

    def del_comments(self, comments):
        pass

    def del_rrset(self):
        if self._zone:
            self._zone._record_deleted(self)

    def _notify_zone(self):
        if self._zone:
            self._zone._record_changed(self)

    def _reg_zone(self, zone):
        self._zone = zone

    def _record_tuple(self):
        return map(lambda x: (x['content'], x['disabled']), self._records)

    def _comment_tuple(self):
        return map(lambda x: (x['content'], x['account'], x['modified_at']), self._comments)

    def __eq__(self, other):
        if type(other) == RRset:
            other_dict = {
                'name': other.name,
                'type': other.type,
                'ttl':  other.ttl,
                'records': Counter(other._record_tuple()),
                'comments': Counter(other._comment_tuple()),
            }
            self_dict = {
                'name': self.name,
                'type': self.type,
                'ttl':  self.ttl,
                'records': Counter(self._record_tuple()),
                'comments': Counter(self._comment_tuple()),
            }
            return self_dict == other_dict
        else:
            return False

class pdnsZoneExists(Exception):
      def __init__(self, expression):
        self.expression = expression