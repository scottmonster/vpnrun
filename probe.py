#!/usr/bin/python3
"""Bounded background-only connectivity probe; no application environment."""
import json
import socket
import sys
import urllib.request


def probe(timeout):
    result = {'dns_ok': False, 'vpn_ok': False}
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo('am.i.mullvad.net', 443, type=socket.SOCK_STREAM)
        result['dns_ok'] = True
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('https://am.i.mullvad.net/json', timeout=timeout) as response:
            result['vpn_ok'] = json.loads(response.read(8192)).get('mullvad_exit_ip') is True
    except Exception:
        pass
    return result


if __name__ == '__main__':
    print(json.dumps(probe(float(sys.argv[1]))))
