import argparse

from analyzer import vpcflow


parser = argparse.ArgumentParser(description="Analyze flow logs")
parser.add_argument("-f", "--flow-log", type=str, required=True, help="log file containing flows logs in ascii format")
parser.add_argument("-l", "--lookup-file", type=str, required=True, help="lookup table in csv format")
parser.add_argument("-o", "--output-dir", type=str, required=True, help="output dir where mappings will be written")
args = parser.parse_args()

vpcflow.main(args.flow_log, args.lookup_file, args.output_dir)
