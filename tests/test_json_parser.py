from pathlib import Path
from textwrap import dedent

import json

from network_tools import json_parser


def test_load_hosts_and_stats(tmp_path):
    payload = {
        "Detail": {
            "host_list": [
                {"host": {"host_id": "1", "ip_v4_address": "10.0.0.1"}},
                {"host": {"host_id": "2", "ip_v4_address": "not-an-ip"}},
            ]
        }
    }
    path = tmp_path / "discovery.json"
    path.write_text(json.dumps(payload))

    hosts = json_parser.load_hosts(path)
    assert len(hosts) == 2
    assert json_parser.count_valid_ipv4(hosts) == 1
    assert "Host 1" in json_parser.format_host(hosts[0], 1)
