from collections import defaultdict
from dataclasses import dataclass
import csv
import os
import sys
import logging

from analyzer import lookup, vpcflow


logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s - %(message)s',
)
logger = logging.getLogger(__name__)

FLOW_VERSION_2_TOTAL_FIELDS = 14
UNTAGGED_KEY = "untagged"


@dataclass
class VpcFlowLog:
    version: int
    account_id: str
    interface_id: str
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    start: int
    end: int
    action: str
    log_status: str


def read_flow_file(filepath):
    try:
        with open(filepath, "r") as f:
            return f.readlines()
    except Exception as ex:
        logger.exception(f"error reading file {filepath}, ex={ex}")
        raise ex

def parse_flow_log(flow_log):
    fields = flow_log.split()
    if len(fields) != FLOW_VERSION_2_TOTAL_FIELDS:
        raise ValueError(f"Flow version 2 format must have {FLOW_VERSION_2_TOTAL_FIELDS} fields")

    try:
        return VpcFlowLog(
            version = int(fields[0]),
            account_id = fields[1],
            interface_id = fields[2],
            src_addr = fields[3],
            dst_addr = fields[4],
            src_port = int(fields[5]),
            dst_port = int(fields[6]),
            protocol = int(fields[7]),
            packets = int(fields[8]),
            bytes = int(fields[9]),
            start = int(fields[10]),
            end = int(fields[11]),
            action = fields[12],
            log_status = fields[13],
        )
    except ValueError as ve:
        logger.exception(f"can't convert log line='{flow_log}'. err={ve}")
        raise ve

def read_flow_logs(flow_file):
    log_lines = read_flow_file(flow_file)
    for line in log_lines:
            yield parse_flow_log(line.strip())

def analyze_flow_logs(flow_file: str, lookup_table: lookup.LookupTable):
    tag_count = defaultdict(int)
    port_proto_count = defaultdict(int)

    logger.info(f"reading flow logs from '{flow_file}'")
    try:
        flow_logs = vpcflow.read_flow_logs(flow_file)
        for log in flow_logs:
            logger.debug(f"processing data: {log}")
            tag = lookup_table.get_tag(log.dst_port, log.protocol)
            if tag:
                logger.debug(f"found tag {tag} for port={log.dst_port}, protocol={log.protocol}")
                tag_count[tag] += 1
                key = (log.dst_port, log.protocol)
                port_proto_count[key] += 1
            else:
                logger.debug(f"untagged port={log.dst_port}, protocol={log.protocol}")
                tag_count[UNTAGGED_KEY] += 1
    except Exception as ex:
        logger.exception(f"unexpected error {ex}")
        raise ex

    logger.debug(f"{tag_count=}")
    logger.debug(f"{port_proto_count=}")
    return tag_count, port_proto_count

def main(flow_file, lookup_file, output_dir):
    lookup_table = lookup.LookupTable(lookup_file)

    try:
        os.makedirs(output_dir)
    except FileExistsError:
        pass
    except OSError as ose:
        logger.exception(f"failed to create output directory: {ose}")

    tag_map, port_proto_map = analyze_flow_logs(flow_file, lookup_table)

    with open(os.path.join(output_dir, "tags.csv"), "w", newline="\n") as csv_file:
        fieldnames = ["tag", "count"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for tag, count in tag_map.items():
            writer.writerow({fieldnames[0]: tag, fieldnames[1]: count})
        logger.info(f"tags written to '{csv_file.name}'")

    with open(os.path.join(output_dir, "port_protocol.csv"), "w", newline="\n") as csv_file:
        fieldnames = ["port", "protocol", "count"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for pp, count in port_proto_map.items():
            writer.writerow({fieldnames[0]: pp[0], fieldnames[1]: pp[1], fieldnames[2]: count})
        logger.info(f"ports & protocols written to '{csv_file.name}'")
