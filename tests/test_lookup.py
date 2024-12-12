import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from analyzer import lookup


def test_lookup_load_and_get(tmpdir):
    with tempfile.NamedTemporaryFile(dir=tmpdir, delete=False) as tf:
        tf.writelines([
            b"dstport,protocol,tag\n",
            b"25,tcp,sv_P1\n",
            b"68,udp,sv_P2\n",
            b"23,tcp,sv_P1",
        ])
        tf.seek(0)

        lookup_table = lookup.LookupTable(tf.name)
        assert len(lookup_table.rows) == 3

        tags = lookup_table.get_tag(port=25, protocol=lookup.protocol_map["TCP"])
        assert tags == "sv_P1"
