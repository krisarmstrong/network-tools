from network_tools import pcap_filter


def test_format_record():
    record = {
        "src_mac": "00:c0:17:aa:bb:cc",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP",
        "src_port": "12345",
        "dst_port": "3842",
        "payload": "abcd",
    }
    text = pcap_filter.format_record(record)
    assert "Source MAC" in text
    assert "abcd" in text
