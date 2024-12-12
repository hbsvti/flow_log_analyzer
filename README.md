# VPC Flow Logs Analyzer

Reads VPC flow logs and tag them using a lookup table.

- Given the max size of flow logs is 10MB, I am simply reading it all in memory. If the flow logs
  were larger (in GBs), we should avoid reading it all in memory. Instead, use techniques like mmap
  or chunking to read it efficiently.

- Similar approach for lookup table. Reading it all in memory as it only has 10k entries.

- **The example shared in the email didn't match the description. I am assuming some log entries
  were missing from the example. Count for port and protocol also seems incorrect. (see Problem Statement section)**

Here is what the code does (based on my understanding of the problem)

1. Reads VPC flow logs in version 2 format.

2. For each log, it will look for destination port and protocol in the lookup table.

   a. If there is a match, it will associate the destination port and protocol with the tag. (all entries
   are counted, not just unique log lines)

   b. If port and protocol is not found, it will be tagged with "untagged" tag.

3. For each destination port and protocol that matched in 2a, it will also maintain a count for them.

## Assumptions

- Only VPC flow logs version 2 is supported.
- Only basic input validation is done.
- The first line in the lookup table should have column names as `dstport`, `protocol`, and `tag`.
- Protocol numbers are from https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml (only first 50 values are supported).

## Requirements

- python >= 3.12
- pytest (if running tests)

## Using Flow Log Analyzer

Run `analyze.py` to analyze/tag VPC flow logs

```
$ cd flow_log_analyzer

$ python analyze.py -h
usage: analyze.py [-h] -f FLOW_LOG -l LOOKUP_FILE -o OUTPUT_DIR
Analyze flow logs

options:
 -h, --help            show this help message and exit
 -f, --flow-log FLOW_LOG
                       log file containing flows logs in ascii format
 -l, --lookup-file LOOKUP_FILE
                       lookup table in csv format
 -o, --output-dir OUTPUT_DIR
                       output dir where mappings will be written
```

For example, running the following

```
$ python analyze.py -f vpcflow.log -l lookup.csv -o output
```

will analyze flow logs in `./vpcflow.log` file using tags from `./lookup.csv` file. The output
files will be stored in `./output` directory.

```
$ ls output
port_protocol.csv  tags.csv
```

`tags.csv` contains count for tags and `port_protocol.csv` contains count for port and protocol.

## Tests

Test are defined under `tests` directory. To run test

1. Install `pytest`

```
$ pip install pytest
```

2. Run test using the following command (pytest config is defined in `pytest.ini`)

```
$ cd flow_log_analyzer
# to run all tests under `tests` dir
$ pytest tests
# to run test for a module (`lookup` in this case)
pytest tests/test_lookup.py
```

---

## Problem Statement

Write a program that can parse a file containing flow log data and maps each row to a tag based
a lookup table. The lookup table is defined as a csv file, and it has 3 columns, dstport,protocol,tag.
The dstport and protocol combination decide what tag can be applied.

**Sample flow logs (default logs, version 2 only).**

```
2 123456789012 eni-0a1b2c3d 10.0.1.201 98.51.100.2 443 49153 6 25 20000 1620140761 1620140821 ACCEPT OK
2 123456789012 eni-4d3c2b1a 192.168.1.100 203.0.113.101 23 49154 6 15 12000 1620140761 1620140821 REJECT OK
2 123456789012 eni-5e6f7g8h 192.168.1.101 198.51.100.3 25 49155 6 10 8000 1620140761 1620140821 ACCEPT OK
2 123456789012 eni-9h8g7f6e 172.16.0.100 203.0.113.102 110 49156 6 12 9000 1620140761 1620140821 ACCEPT OK
2 123456789012 eni-7i8j9k0l 172.16.0.101 192.0.2.203 993 49157 6 8 5000 1620140761 1620140821 ACCEPT OK
2 123456789012 eni-6m7n8o9p 10.0.2.200 198.51.100.4 143 49158 6 18 14000 1620140761 1620140821 ACCEPT OK
2 123456789012 eni-1a2b3c4d 192.168.0.1 203.0.113.12 1024 80 6 10 5000 1620140661 1620140721 ACCEPT OK
2 123456789012 eni-1a2b3c4d 203.0.113.12 192.168.0.1 80 1024 6 12 6000 1620140661 1620140721 ACCEPT OK
2 123456789012 eni-1a2b3c4d 10.0.1.102 172.217.7.228 1030 443 6 8 4000 1620140661 1620140721 ACCEPT OK
2 123456789012 eni-5f6g7h8i 10.0.2.103 52.26.198.183 56000 23 6 15 7500 1620140661 1620140721 REJECT OK
2 123456789012 eni-9k10l11m 192.168.1.5 51.15.99.115 49321 25 6 20 10000 1620140661 1620140721 ACCEPT OK
2 123456789012 eni-1a2b3c4d 192.168.1.6 87.250.250.242 49152 110 6 5 2500 1620140661 1620140721 ACCEPT OK
2 123456789012 eni-2d2e2f3g 192.168.2.7 77.88.55.80 49153 993 6 7 3500 1620140661 1620140721 ACCEPT OK
2 123456789012 eni-4h5i6j7k 172.16.0.2 192.0.2.146 49154 143 6 9 4500 1620140661 1620140721 ACCEPT OK
```

**For e.g. the lookup table file can be something like:**

```
dstport,protocol,tag
25,tcp,sv_P1
68,udp,sv_P2
23,tcp,sv_P1
31,udp,SV_P3
443,tcp,sv_P2
22,tcp,sv_P4
3389,tcp,sv_P5
0,icmp,sv_P5
110,tcp,email
993,tcp,email
143,tcp,email
```

**The program should generate an output file containing the following:**

- **Count of matches for each tag, sample o/p shown below**
  Tag Counts:

```
Tag,Count
sv_P2,1
sv_P1,2
sv_P4,1 X (LOGS SHOULD HAVE ENTRY WITH dstport=22)
email,3
Untagged,9
```

- **Count of matches for each port/protocol combination**
  Port/Protocol Combination Counts:

```
Port,Protocol,Count
22,tcp,1 X (THIS ENTRY CORRESPONDS TO sv_P4)
23,tcp,1
25,tcp,1
110,tcp,1
143,tcp,1
443,tcp,1
993,tcp,1
1024,tcp,1 X (NOT SURE WHAT NEXT 3 ENTRIES MAP TO, THEY ARE NOT THERE IN LOOKUP TABLE)
49158,tcp,1 X
80,tcp,1 X
```

**Requirement details**

- Input file as well as the file containing tag mappings are plain text (ascii) files
- The flow log file size can be up to 10 MB
- The lookup file can have up to 10000 mappings
- The tags can map to more than one port, protocol combinations. for e.g. sv_P1 and sv_P2 in the sample above.
