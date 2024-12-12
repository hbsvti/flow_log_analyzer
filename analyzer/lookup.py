import csv
import logging

from dataclasses import dataclass


# protocol numbers from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
# NOTE: only contains upto first 50 protocols.
protocol_map = {
    "HOPOPT": 0,
    "ICMP": 1,
    "IGMP": 2,
    "GGP": 3,
    "IPv4": 4,
    "ST": 5,
    "TCP": 6,
    "CBT": 7,
    "EGP": 8,
    "IGP": 9,
    "BBN": 10,
    "NVP": 11,
    "PUP": 12,
    "ARGUS": 13,
    "EMCON": 14,
    "XNET": 15,
    "CHAOS": 16,
    "UDP": 17,
    "MUX": 18,
    "DCN": 19,
    "HMP": 20,
    "PRM": 21,
    "XNS": 22,
    "TRUNK-1": 23,
    "TRUNK-2": 24,
    "LEAF-1": 25,
    "LEAF-2": 26,
    "RDP": 27,
    "IRTP": 28,
    "ISO-TP4": 29,
    "NETBLT": 30,
    "MFE": 31,
    "MERIT": 32,
    "DCCP": 33,
    "3PC": 34,
    "IDPR": 35,
    "XTP": 36,
    "DDP": 37,
    "IDPR-CMTP": 38,
    "TP++": 39,
    "IL": 40,
    "IPv6": 41,
    "SDRP": 42,
    "IPv6-Route": 43,
    "IPv6-Frag": 44,
    "IDRP": 45,
    "RSVP": 46,
    "GRE": 47,
    "DSR": 48,
    "BNA": 49,
    "ESP": 50,
}

logger = logging.getLogger(__name__)

@dataclass
class LookupRow:
    dstport: int
    protocol: int
    tag: str


class LookupTable:
    def __init__(self, lookup_file):
        self.lookup_file: str = lookup_file
        self.rows: list[LookupRow] = []
        self.port_proto_dict: dict = {}
        self._load_lookup_file()

    def get_tag(self, port: int, protocol: int):
        row = LookupRow(dstport=port, protocol=protocol, tag="")
        key = self._row_hash(row)
        return self.port_proto_dict.get(key)


    def _row_hash(self, row: LookupRow):
        return f"{row.dstport}:{row.protocol}"

    def _add(self, row: LookupRow):
        self.rows.append(row)
        item = self._row_hash(row)
        self.port_proto_dict[item] = row.tag

    def _load_lookup_file(self):
        logger.info(f"loading lookup file '{self.lookup_file}'")
        with open(self.lookup_file, 'r') as f:
            reader = csv.DictReader(f, strict=True)
            for row in reader:
                # only basic validation is done here, doesn't verify things like protocol has a valid entry
                if row['protocol'] is None or row['dstport'] is None or row['tag'] is None:
                    raise ValueError(f"Invalid lookup table {self.lookup_file}. Not all values found {row}")

                proto_num = protocol_map[row['protocol'].upper()]
                lk_row = LookupRow(dstport=int(row['dstport']), protocol=proto_num, tag=row['tag'])
                self._add(lk_row)
            logger.info(f"loaded lookup table, row count={len(self.rows)}")
            logger.debug(f"lookup table rows={self.rows}")
