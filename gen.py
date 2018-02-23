#!/usr/bin/env python3

import collections
import json
import os
import re
import requests
import tempfile

from netaddr import IPNetwork

wanted_aut = (
            ('ovh',       r'OVH\s*,\s*FR'),
            ('uk-bt',     r'BTnet UK Regional network'),
            ('uk-bskyb',  r'BSKYB-BROADBAND-AS\s*,\s*GB'),
            ('uk-orange', r'ORANGE-PCS\s*,\s*GB'),
            ('uk-virgin', r'NTL\s*,\s*GB'),
)


def main():
    download('https://ip-ranges.amazonaws.com/ip-ranges.json',
             'cache/aws-ranges.json')

    download('http://thyme.apnic.net/current/data-raw-table',
             'cache/thyme-table')

    download('http://thyme.apnic.net/current/data-used-autnums',
             'cache/thyme-autnums')

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

    del aws

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
    blocks = sorted((IPNetwork(ip) for ip in ips), key=lambda ip: ip.prefixlen)
    existing = []
    for block in blocks:
        if not any_contain(existing, block):
            existing.append(block)
    return sorted(existing)


def download(url, dest):
    headers = {}
    try:
        headers['If-Modified-Since'] = to_date(os.path.getmtime(dest))
    except Exception as _:
        pass

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
    return formatdate(timeval=timestamp, localtime=False, usegmt=True)


def printf(msg):
    print(msg, end='', flush=True)


if '__main__' == __name__:
    main()