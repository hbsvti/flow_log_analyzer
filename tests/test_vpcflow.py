import os
import sys
import pytest
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from analyzer import vpcflow, lookup


def test_parse_valid_log_line():
    log_line = "2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK"
    flow_log = vpcflow.parse_flow_log(log_line)
    assert flow_log.version == 2
    assert flow_log.account_id == "123456789012"
    assert flow_log.interface_id == "eni-0a1b2c3d"
    assert flow_log.src_addr == "10.0.1.201"
    assert flow_log.dst_addr == "198.51.100.2"
    assert flow_log.src_port == 443
    assert flow_log.dst_port == 49153
    assert flow_log.protocol == 6
    assert flow_log.packets == 25
    assert flow_log.bytes == 20000
    assert flow_log.start == 1620140761
    assert flow_log.end == 1620140821
    assert flow_log.action == "ACCEPT"
    assert flow_log.log_status == "OK"

def test_parse_log_line_missing_fields():
    log_line = "2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2"
    with pytest.raises(ValueError):
        vpcflow.parse_flow_log(log_line)

def test_parse_log_line_invalid_field_type():
    log_line = "2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 4.4.3 49153 6 25 20000 1620140761 1620140821 ACCEPT OK"
    with pytest.raises(ValueError):
        vpcflow.parse_flow_log(log_line)

def test_no_tag_match(tmpdir):
    with (tempfile.NamedTemporaryFile(dir=tmpdir, delete=True) as flow_file,
          tempfile.NamedTemporaryFile(dir=tmpdir, delete=True) as lookup_file):
        flow_file.writelines([
            b"2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n",
            b"2 123456789012 eni-5f6g7h8i 10.0.2.103 52.26.198.183 56000 33 6 15 7500 1620140661 1620140721 REJECT OK\n"
            b"2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 23 49154 6 15 12000 1620140761 1620140821 REJECT OK\n",
        ])
        flow_file.seek(0)

        lookup_file.writelines([
            b"dstport,protocol,tag\n",
            b"25,tcp,sv_P1\n",
            b"68,udp,sv_P2\n",
            b"23,tcp,sv_P1",
        ])
        lookup_file.seek(0)

        lookup_table = lookup.LookupTable(lookup_file.name)
        tags, ports = vpcflow.analyze_flow_logs(flow_file.name, lookup_table)

        assert len(tags) == 1
        assert tags[vpcflow.UNTAGGED_KEY] == 3
        assert len(ports) == 0

def test_tag_single_port_map(tmpdir):
    with (tempfile.NamedTemporaryFile(dir=tmpdir, delete=True) as flow_file,
          tempfile.NamedTemporaryFile(dir=tmpdir, delete=True) as lookup_file):
        flow_file.writelines([
            b"2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n",
            b"2 123456789012 eni-5f6g7h8i 10.0.2.103 52.26.198.183 56000 25 6 15 7500 1620140661 1620140721 REJECT OK\n"
            b"2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 23 49154 6 15 12000 1620140761 1620140821 REJECT OK\n",
        ])
        flow_file.seek(0)

        lookup_file.writelines([
            b"dstport,protocol,tag\n",
            b"25,tcp,sv_P1\n",
            b"68,udp,sv_P2\n",
        ])
        lookup_file.seek(0)

        lookup_table = lookup.LookupTable(lookup_file.name)
        tags, ports = vpcflow.analyze_flow_logs(flow_file.name, lookup_table)

        assert len(tags) == 2
        assert tags["sv_P1"] == 1
        assert tags[vpcflow.UNTAGGED_KEY] == 2

        assert len(ports) == 1
        assert ports[(25, 6)] == 1

def test_tag_multiple_port_map(tmpdir):
    with (tempfile.NamedTemporaryFile(dir=tmpdir, delete=True) as flow_file,
          tempfile.NamedTemporaryFile(dir=tmpdir, delete=True) as lookup_file):
        flow_file.writelines([
            b"2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n",
            b"2 123456789012 eni-5f6g7h8i 10.0.2.103 52.26.198.183 56000 23 6 15 7500 1620140661 1620140721 REJECT OK\n"
            b"2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 23 49154 6 15 12000 1620140761 1620140821 REJECT OK\n",
            b"2 123456789012 eni-4h5i6j7k 172.16.0.2 192.0.2.146 49154 143 6 9 4500 1620140661 1620140721 ACCEPT OK\n",
            b"2 123456789012 eni-2d2e2f3g 192.168.2.7 77.88.55.80 993 68 17 7 3500 1620140661 1620140721 ACCEPT OK\n",
            b"2 123456789012 eni-9k10l11m 192.168.1.5 51.15.99.115 49321 25 6 20 10000 1620140661 1620140721 ACCEPT OK\n",
        ])
        flow_file.seek(0)

        lookup_file.writelines([
            b"dstport,protocol,tag\n",
            b"25,tcp,sv_P1\n",
            b"68,udp,sv_P2\n",
            b"23,tcp,sv_P1",
        ])
        lookup_file.seek(0)

        lookup_table = lookup.LookupTable(lookup_file.name)
        tags, ports = vpcflow.analyze_flow_logs(flow_file.name, lookup_table)

        assert len(tags) == 3
        assert tags["sv_P1"] == 2
        assert tags["sv_P2"] == 1
        assert tags[vpcflow.UNTAGGED_KEY] == 3

        assert len(ports) == 3
        assert set(ports.keys()) == set([(23, 6), (25, 6), (68, 17)])

def test_repeated_entries(tmpdir):
    with (tempfile.NamedTemporaryFile(dir=tmpdir, delete=True) as flow_file,
          tempfile.NamedTemporaryFile(dir=tmpdir, delete=True) as lookup_file):
        flow_file.writelines([
            b"2 123456789012 eni-0a1b2c3d 10.0.1.201 198.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK\n",
            b"2 123456789012 eni-5f6g7h8i 10.0.2.103 52.26.198.183 56000 25 6 15 7500 1620140661 1620140721 REJECT OK\n"
            b"2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 443 49154 6 15 12000 1620140761 1620140821 REJECT OK\n",
            b"2 123456789012 eni-5f6g7h8i 10.0.2.101 52.26.198.183 56000 25 6 15 6500 1620140661 1620140721 ACCEPT OK\n"
            b"2 123456789012 eni-5f6g7h8i 10.0.2.111 52.26.198.183 56000 25 6 15 4500 1620140661 1620140721 ACCEPT OK\n"
        ])
        flow_file.seek(0)

        lookup_file.writelines([
            b"dstport,protocol,tag\n",
            b"25,tcp,sv_P1\n",
            b"68,udp,sv_P2\n",
        ])
        lookup_file.seek(0)

        lookup_table = lookup.LookupTable(lookup_file.name)
        tags, ports = vpcflow.analyze_flow_logs(flow_file.name, lookup_table)

        assert len(tags) == 2
        assert tags["sv_P1"] == 3
        assert tags[vpcflow.UNTAGGED_KEY] == 2

        assert len(ports) == 1
        assert set(ports.keys()) == set([(25, 6)])
