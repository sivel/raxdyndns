#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2013 Matt Martz
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import pyrax
import requests
import socket
import sys
import json
import os
import yaml
import logging
import keyring
import raxdyndns.exceptions as exc


class RaxDynDns(object):
    def __init__(self):
        exists, self.log_file = self.find_file('raxdyndns.log')
        self.logger = logging.getLogger('raxdyndns')
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(self.log_file)
        fmt = ('%(asctime)s %(name)s[%(process)d] [%(levelname)s] '
               '%(message)s')
        datefmt = '%b %d %H:%M:%S'
        formatter = logging.Formatter(fmt, datefmt)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        self.logger.info('Opened log file %s' % self.log_file)

        exists, self.config_file = self.find_file('raxdyndns.yaml')
        if not exists:
            raise exc.ConfigFileNotFound(
                'Configuration file (raxdyndns.yaml) not found')
        with open(self.config_file, 'r') as f:
            self.config = yaml.load(f)

        exists, self.cache_file = self.find_file('raxdyndns-cache.json')
        self.logger.info('Setting %s as cache file' % self.cache_file)

    def find_file(self, filename):
        locations = [
            '.',
            '~/.raxdyndns',
            '~',
            '/etc/raxdyndns',
            '/etc/'
        ]
        for location in locations:
            path = os.path.join(os.path.abspath(os.path.expanduser(location)),
                                filename)
            if os.path.isfile(path):
                break
            path = None
        if path:
            return True, path
        else:
            return False, os.path.join(
                os.path.abspath(os.path.expanduser(locations[0])), filename)

    def config_get(self, section, key=None, default=None):
        config_section = self.config.get(section)
        if key is None:
            return config_section
        value = config_section.get(key, default)
        if value == 'USE_KEYRING':
            keyring_path = '%s/%s' % (section, key)
            keyring_value = keyring.get_password('serverherald', keyring_path)
            if keyring_value is None:
                raise exc.EmptyKeyring('%s is not configured' % keyring_path)
            return keyring_value
        else:
            return value

    def load_cache(self):
        try:
            with open(self.cache_file) as f:
                ip_addresses = json.load(f)
        except (IOError, ValueError, TypeError):
            ip_addresses = {'ipv4': None, 'ipv6': None}
        self.logger.info('Loaded (%s) from cache' % ip_addresses)
        return ip_addresses

    def save_cache(self, ip_addresses=None):
        if not ip_addresses:
            ip_addresses = self.current
        with open(self.cache_file, 'w+') as f:
            json.dump(ip_addresses, f)
        self.logger.info('Saved (%s) to cache' % ip_addresses)

    def get_ips(self):
        af_types = {
            'ipv4': socket.AF_INET,
            'ipv6': socket.AF_INET6
        }
        ip_addresses = {'ipv4': None, 'ipv6': None}
        for ip_type in ip_addresses:
            try:
                r = requests.get('http://%s.icanhazip.com/' % ip_type)
                r.raise_for_status()
            except:
                continue
            else:
                ip = r.text.strip()

            try:
                socket.inet_pton(af_types[ip_type], ip)
            except socket.error:
                continue
            else:
                ip_addresses[ip_type] = ip

        self.logger.info('Current IP Addresses %s' % ip_addresses)
        return ip_addresses

    def check_ips(self):
        self.cache = self.load_cache()
        self.current = self.get_ips()

        updated = False
        new = {'ipv4': None, 'ipv6': None}
        for ip_type, ip in self.current.iteritems():
            if ip != self.cache[ip_type]:
                new[ip_type] = ip
                updated = True

        if updated:
            self.logger.info('IP addresses are to be updated (%s)' % new)
            return new
        else:
            self.logger.info('IP addresses have not changed')
            return False

    def update_records(self, ip_addresses):
        record_types = {
            'ipv4': 'A',
            'ipv6': 'AAAA'
        }
        username = self.config_get('username')
        if username is None:
            raise exc.NoUsername('A username is not configured in %s' %
                                 self.config_file)
        apikey = self.config_get('apikey')
        if apikey is None:
            raise exc.NoApiKey('An API key is not configured in %s' %
                               self.config_file)
        pyrax.set_setting('identity_type', 'rackspace')
        pyrax.set_credentials(username, apikey)
        self.dns = pyrax.cloud_dns
        dns_info = self.find_dns()
        for ip_type, ip in ip_addresses.iteritems():
            if ip is None:
                continue
            if dns_info[ip_type] is None:
                self.logger.info('Creating %s record for %s' %
                                 (record_types[ip_type], dns_info['host']))
                records = dns_info['domain'].add_records([
                    {
                        'type': record_types[ip_type],
                        'name': dns_info['host'],
                        'data': ip,
                        'ttl': 300
                    }
                ])
            else:
                self.logger.info('Updating %s record for %s' %
                                 (record_types[ip_type], dns_info['host']))
                if isinstance(dns_info[ip_type], dict):
                    record_obj = dns.CloudDNSRecord(dns, dns_info[ip_type],
                                                    loaded=False)
                    dns_info['domain'].update_record(record_obj, data=ip)
                else:
                    dns_info[ip_type].update(data=ip)

    def find_dns(self):
        domain = self.config_get('domain')
        host = self.config_get('host')
        if not host:
            raise exc.NoHost('A host is not conffigured in %s' %
                             self.config_file)
        if not domain or '.' not in domain:
            if '.' not in host:
                raise exc.CannotDetermineHost('A proper domain was not '
                                              'provided and a fully qualified '
                                              'domain name was not provided '
                                              'for the host configuration')
            host_parts = host.split('.')
            if len(host_parts) == 2:
                domain = host
            else:
                domain = '.'.join(host_parts[1:])
            self.logger.warning('A domain was not configured, attempting to '
                                'use %s as determined from the configured '
                                'host' % domain)

        if '.' not in host:
            self.logger.warning('A FQDN was not proivided for the host, '
                                'appending the domain (%s) to the host (%s): '
                                '%s' % (domain, host,
                                        '%s.%s' % (host, domain)))
            host = '%s.%s' % (host, domain)
        if not host.endswith(domain):
            raise exc.HostDomainMismatch('The provided host does not match '
                                         'the provided domain')

        domain_objs = self.dns.findall(name=domain)
        if not domain_objs:
            raise exc.DomainNotFound('A domain matching %s was not found in '
                                     'your account' % domain)
        domain_obj = domain_objs[0]
        self.logger.info('Found %s: %s' % (domain_obj.id, domain_obj.name))

        try:
            ipv4_record_obj = domain_obj.find_record('A', host)
            self.logger.info('Found %s: %s' %
                             (ipv4_record_obj.id, ipv4_record_obj.name))
        except pyrax.exceptions.DomainRecordNotFound:
            self.logger.warning('A record not found, will be created')
            ipv4_record_obj = None
        try:
            ipv6_record_obj = domain_obj.find_record('AAAA', host)
            self.logger.info('Found %s: %s' %
                             (ipv6_record_obj.id, ipv6_record_obj.name))
        except pyrax.exceptions.DomainRecordNotFound:
            self.logger.warning('AAAA record not found')
            ipv6_record_obj = None

        return {
            'domain': domain_obj,
            'host': host,
            'ipv4': ipv4_record_obj,
            'ipv6': ipv6_record_obj
        }


def main():
    try:
        rdyn = RaxDynDns()
        ip_addresses = rdyn.check_ips()
        if ip_addresses:
            rdyn.update_records(ip_addresses)
            rdyn.save_cache()
    except:
        e = sys.exc_info()[0]
        rdyn.logger.error(e)
        raise SystemExit(e)

# vim:set ts=4 sw=4 expandtab:
