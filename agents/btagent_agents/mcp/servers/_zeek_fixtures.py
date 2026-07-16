"""Recorded Zeek / Corelight fixtures for mock-mode responses (#100).

Shapes mirror native Zeek log columns (``ts`` / ``uid`` / ``id.orig_h`` …) so
prompts and downstream parsing exercise the real field vocabulary:

- ``ZEEK_FIXTURE_LOGS`` — rows keyed by log type (``conn`` / ``dns`` /
  ``ssl`` / ``notice``), the log-search mock's data source.

The fixtures tell one coherent DNS-tunneling + beaconing story on
``10.7.3.44`` (WS-ENG-11):

* Three metronomic ~60s-apart TLS connections to ``198.51.100.150:443``
  with tiny payloads (the beacon), then one long-lived, large-upload
  connection (the exfil push).
* High-entropy subdomain lookups under ``tunnel.example-cdn.net``
  (T1071.004 / T1048.003) next to ordinary corporate lookups.
* The beacon destination presents a self-signed certificate
  (``validation_status: self signed certificate``).
* ``notice`` rows: the invalid-cert notice for the beacon destination, a
  DNS-tunneling heuristic notice for ``10.7.3.44``, and an unrelated
  address-scan notice from ``10.7.5.9`` (the noise floor).

Join keys: ``uid`` ties a conn row to its dns/ssl enrichment rows exactly as
Zeek does; ``id.orig_h`` / ``src`` carries the host pivot on every surface.
"""

from __future__ import annotations

from typing import Any

ZEEK_FIXTURE_LOGS: dict[str, list[dict[str, Any]]] = {
    "conn": [
        # --- the beacon: metronomic, tiny, TLS ---
        {
            "ts": "2026-06-20T09:00:05Z",
            "uid": "CZbeac1aaaaaaaaaaa",
            "id.orig_h": "10.7.3.44",
            "id.orig_p": 49812,
            "id.resp_h": "198.51.100.150",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 1.2,
            "orig_bytes": 412,
            "resp_bytes": 380,
            "conn_state": "SF",
        },
        {
            "ts": "2026-06-20T09:01:06Z",
            "uid": "CZbeac2bbbbbbbbbbb",
            "id.orig_h": "10.7.3.44",
            "id.orig_p": 49844,
            "id.resp_h": "198.51.100.150",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 1.1,
            "orig_bytes": 408,
            "resp_bytes": 391,
            "conn_state": "SF",
        },
        {
            "ts": "2026-06-20T09:02:04Z",
            "uid": "CZbeac3ccccccccccc",
            "id.orig_h": "10.7.3.44",
            "id.orig_p": 49871,
            "id.resp_h": "198.51.100.150",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 1.3,
            "orig_bytes": 415,
            "resp_bytes": 377,
            "conn_state": "SF",
        },
        # --- the exfil push: long-lived, upload-heavy ---
        {
            "ts": "2026-06-20T09:15:00Z",
            "uid": "CZexfil4ddddddddddd",
            "id.orig_h": "10.7.3.44",
            "id.orig_p": 50102,
            "id.resp_h": "198.51.100.150",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 940.0,
            "orig_bytes": 48_302_115,
            "resp_bytes": 22_410,
            "conn_state": "SF",
        },
        # --- ordinary corporate traffic (noise floor) ---
        {
            "ts": "2026-06-20T09:03:10Z",
            "uid": "CZnorm5eeeeeeeeeee",
            "id.orig_h": "10.7.3.44",
            "id.orig_p": 51230,
            "id.resp_h": "10.0.0.53",
            "id.resp_p": 53,
            "proto": "udp",
            "service": "dns",
            "duration": 0.02,
            "orig_bytes": 60,
            "resp_bytes": 145,
            "conn_state": "SF",
        },
        {
            "ts": "2026-06-20T09:04:00Z",
            "uid": "CZnorm6fffffffffff",
            "id.orig_h": "10.7.5.9",
            "id.orig_p": 42100,
            "id.resp_h": "10.0.8.20",
            "id.resp_p": 445,
            "proto": "tcp",
            "service": "smb",
            "duration": 3.5,
            "orig_bytes": 2_100,
            "resp_bytes": 8_744,
            "conn_state": "SF",
        },
    ],
    "dns": [
        # --- tunneling queries: long high-entropy labels, TXT records ---
        {
            "ts": "2026-06-20T09:00:04Z",
            "uid": "CZdns1ggggggggggg",
            "id.orig_h": "10.7.3.44",
            "id.resp_h": "10.0.0.53",
            "query": "aGVsbG8gd29ybGQx.c2VjcmV0cGF5bG9hZA.tunnel.example-cdn.net",
            "qtype_name": "TXT",
            "rcode_name": "NOERROR",
            "answers": ["ok1"],
        },
        {
            "ts": "2026-06-20T09:01:05Z",
            "uid": "CZdns2hhhhhhhhhhh",
            "id.orig_h": "10.7.3.44",
            "id.resp_h": "10.0.0.53",
            "query": "ZXhmaWwtY2h1bms.dGhpcmR0cmFuY2hl.tunnel.example-cdn.net",
            "qtype_name": "TXT",
            "rcode_name": "NOERROR",
            "answers": ["ok2"],
        },
        # --- beacon destination resolution ---
        {
            "ts": "2026-06-20T09:00:03Z",
            "uid": "CZdns3iiiiiiiiiii",
            "id.orig_h": "10.7.3.44",
            "id.resp_h": "10.0.0.53",
            "query": "cdn-sync.example-cdn.net",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
            "answers": ["198.51.100.150"],
        },
        # --- ordinary lookup (noise floor) ---
        {
            "ts": "2026-06-20T09:03:09Z",
            "uid": "CZnorm5eeeeeeeeeee",
            "id.orig_h": "10.7.3.44",
            "id.resp_h": "10.0.0.53",
            "query": "mail.example.com",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
            "answers": ["10.0.4.10"],
        },
    ],
    "ssl": [
        # --- the beacon's self-signed certificate ---
        {
            "ts": "2026-06-20T09:00:05Z",
            "uid": "CZbeac1aaaaaaaaaaa",
            "id.orig_h": "10.7.3.44",
            "id.resp_h": "198.51.100.150",
            "version": "TLSv12",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "server_name": "cdn-sync.example-cdn.net",
            "subject": "CN=localhost",
            "issuer": "CN=localhost",
            "validation_status": "self signed certificate",
        },
        # --- ordinary corporate TLS (noise floor) ---
        {
            "ts": "2026-06-20T09:05:00Z",
            "uid": "CZnorm7jjjjjjjjjjj",
            "id.orig_h": "10.7.3.44",
            "id.resp_h": "203.0.113.30",
            "version": "TLSv13",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "server_name": "www.example.com",
            "subject": "CN=www.example.com,O=Example Corp",
            "issuer": "CN=Example Global CA",
            "validation_status": "ok",
        },
    ],
    "notice": [
        {
            "ts": "2026-06-20T09:00:06Z",
            "uid": "CZbeac1aaaaaaaaaaa",
            "note": "SSL::Invalid_Server_Cert",
            "msg": "SSL certificate validation failed with (self signed certificate)",
            "src": "10.7.3.44",
            "dst": "198.51.100.150",
        },
        {
            "ts": "2026-06-20T09:02:10Z",
            "uid": "CZdns2hhhhhhhhhhh",
            "note": "CorelightLabs::DNS_Tunneling",
            "msg": (
                "Possible DNS tunneling: high-entropy TXT queries under "
                "tunnel.example-cdn.net from 10.7.3.44"
            ),
            "src": "10.7.3.44",
            "dst": "10.0.0.53",
        },
        {
            "ts": "2026-06-20T08:40:00Z",
            "uid": "CZscan8kkkkkkkkkkk",
            "note": "Scan::Address_Scan",
            "msg": "10.7.5.9 scanned at least 25 hosts on 445/tcp in 5m",
            "src": "10.7.5.9",
            "dst": "",
        },
    ],
}
