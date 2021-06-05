#!/usr/bin/env python3

import collections
import json
import os
import re
import tempfile
from typing import Iterator, List

import dns.resolver
import requests
from netaddr import IPNetwork, IPSet

wanted_aut = (
            ('alibaba',   r'(?i)Alibaba'),
            ('google',    r'(?i)Google'),
            ('microsoft', r'(?i)Microsoft'),
            ('ovh',       r'OVH\s*,\s*FR'),
            ('uk-bt',     r'BTnet UK Regional network'),
            ('uk-bskyb',  r'BSKYB-BROADBAND-AS\s*,\s*GB'),
            ('uk-orange', r'ORANGE-PCS\s*,\s*GB'),
            ('uk-virgin', r'NTL\s*,\s*GB'),
)


def main():
    os.makedirs('cache', exist_ok=True)
    download('https://ip-ranges.amazonaws.com/ip-ranges.json',
             'cache/aws-ranges.json')

    download('http://thyme.apnic.net/current/data-raw-table',
             'cache/thyme-table')

    download('http://thyme.apnic.net/current/data-used-autnums',
             'cache/thyme-autnums')

    do_aws()
    do_google()

    wanted_re = [(k, re.compile(v)) for (k, v) in wanted_aut]
    line_re = re.compile(r'\s*(\d+)\s+(.*)')

    aut_ids = collections.defaultdict(set)
    with open('cache/thyme-autnums', encoding='windows-1251') as f:
        for line in f:
            line = line.strip()
            ma = line_re.match(line)
            id = int(ma.group(1))
            name = ma.group(2)
            for (key, reg) in wanted_re:
                if reg.search(name):
                    aut_ids[id].add(key)

    aut = collections.defaultdict(set)
    with open('cache/thyme-table') as f:
        for line in f:
            line = line.strip()
            (block, id) = line.split('\t', 2)
            id = int(id)
            if id not in aut_ids:
                continue
            for key in aut_ids[id]:
                aut[key].add(block)

    for (key, ips) in aut.items():
        if 0 == len(ips):
            print('warning: nothing generated for {}'.format(key))
            continue
        with open('ip-whitelist.d/{}.lst'.format(key), 'w') as f:
            write_out(f, ips)

    print('Done!')


def do_aws():
    aws = collections.defaultdict(set)
    with open('cache/aws-ranges.json') as f:
        for obj in json.load(f)['prefixes']:
            if 'EC2' != obj['service']:
                continue
            aws[obj['region']].add(obj['ip_prefix'])
    for (region, ips) in aws.items():
        assert '/' not in region
        with open('ip-whitelist.d/aws-ec2-{}.lst'.format(region), 'w') as f:
            write_out(f, ips)


def spf_parts(host: str) -> Iterator[str]:
    for record in dns.resolver.query(host, dns.rdatatype.TXT):
        for string in record.strings:
            yield from re.split(r'\s+', string.decode('utf-8'))


def spf_ips(host: str) -> Iterator[str]:
    for record in spf_parts(host):
        if 'v=spf1' == record:
            continue
        elif record.startswith('include:'):
            yield from spf_ips(record[len('include:'):])
        elif record in ['?all', '~all']:
            continue
        elif record.startswith('ip4:'):
            yield record[len('ip4:'):]
        elif record.startswith('ip6:'):
            yield record[len('ip6:'):]
        else:
            raise Exception("unexpected token: " + record)


def do_google():
    with open('ip-whitelist.d/google-gce.lst', 'w') as f:
        write_out(f, list(spf_ips('_cloud-netblocks.googleusercontent.com')))


def write_out(f, ips):
    f.write('# generated\n\n')
    for ip in simplify(ips):
        f.write(str(ip))
        f.write('\n')


def any_contain(existing, block):
    for ex in existing:
        if block in ex:
            return True
    return False


def simplify(ips):
    """
    Remove duplicates and entirely overlapping blocks,
    and sort by "version"
    """
    nets = IPSet(ips)
    return sorted(nets.iter_cidrs())


def download(url, dest):
    headers = {}
    try:
        headers['If-Modified-Since'] = to_date(os.path.getmtime(dest))
    except Exception as e:
        print("Couldn't send last modified, ignoring:", e)

    printf('Checking {}... '.format(url))
    r = requests.get(url, stream=True, headers=headers)

    if 304 == r.status_code:
        print('not modified.')
        return

    if 200 != r.status_code:
        raise Exception('failed to download: ' + r)

    printf('downloading...')
    (f, path) = tempfile.mkstemp(dir='cache', prefix='.fetch', suffix='.tmp')
    f = open(f, 'wb')
    for chunk in r.iter_content(chunk_size=32 * 1024):
        if chunk:
            printf('.')
            f.write(chunk)
    f.close()

    # save old mtime
    modified = r.headers['last-modified']
    if modified:
        when = from_date(modified)
        os.utime(path, (when, when))
    os.rename(path, dest)
    print('. done.')


def from_date(header):
    from email.utils import parsedate
    import time
    return time.mktime(parsedate(header))


def to_date(timestamp):
    from email.utils import formatdate
    return formatdate(timeval=timestamp, localtime=True, usegmt=True)


def printf(msg):
    print(msg, end='', flush=True)


if '__main__' == __name__:
    main()
