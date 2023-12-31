"""
From: Nick Petersen
Email: 77npete@gmail.com

This script can compare a pcap or group of pcaps in "dir1" to a pcap or group of pcaps in "dir2" in order to
assess if there are any (IP) packets missing in the pcaps from dir2 as compared to pcap(s) in dir1.
Written such that it can assess many large pcaps in a relatively time efficient manner.
Packets that are missing can optionally be written to a new pcap file for more detail analysis.

This script makes use of the scapy packet and pcap module: https://scapy.readthedocs.io/en/latest/ for
reading/writing pcap files and for the structure of packets and packet lists in python.

Packet matching compares packets based on a combination of the following parameters
 * IP ID: a unique ID given to packets in a session
 * Source IP
 * Destination IP
 * L4 Protocol
 [For TCP & UDP]
   * Source Port
   * Destination Port
 [For ICMP & ICMPv6]
   * Type
   * Code

All packets that are not IP (LLDP, ARP, STP, Etc.) are skipped. And only L4 protocols TCP, UDP, ICMP & ICMPv6 are
currently supported.

It is possible that if there is little or no entropy in a test environment that these can be duplicated, it is unlikely
in the real world during within a packet capture time frame and in a test environment adding entropy with src/dest IPs
will make this unlikely.  Has been tested in Ixia lab with emix and /24 client and server subnets with no issue on up to
1G of main and match packets captures.

Currently, all output and details are sent to the console, the exception being the "missing packets pcap" that is
generated if that option is set to True.

"""
from nppcapy import *
from scapy.all import *
import os
import time
import datetime
import pathlib
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--debug', type=bool, default=False, help='enable/disable debug output to console')
parser.add_argument('-c', '--compare', type=bool, default=True, help='run actual pkt check between pcaps in dir1/dir2')
parser.add_argument('-o', '--output_pcap', type=bool, default=False, help='output pcap of missing packets when compare')
parser.add_argument('-t', '--tcp_reset', type=bool, default=False, help='check and calculate number of tcp resets')
parser.add_argument('-l', '--list_pcaps', type=bool, default=False, help='print list of pcaps to process to console')
parser.add_argument('-f', '--flip_pcaps', type=bool, default=False, help='fip direction of comparison of pcap dirs')
parser.add_argument('-T', '--timer', type=bool, default=True, help='print time taken to execute')
parser.add_argument('--pcap_dir_main', type=str, required=True,
                    help='Path relative/absolute to the directory containing pcaps to check for missing packets')
parser.add_argument('--pcap_dir_match', type=str, required=True,
                    help='Path relative/absolute to the directory containing pcaps to compare against')
parser.add_argument('-r', '--results_dir', type=str, default='./', help='directory path for any output incl. pcaps')

parser.add_argument('--max_main_pcaps', type=int, default=0, help='The max number of pcaps from "main" pcap '
                    'directory to process. 0=unlimited. This is primarily for troubleshooting or pre-run checks')
parser.add_argument('--max_match_pcaps', type=int, default=0, help='the max number of pcaps from "match" pcap '
                    'directory to process. 0=unlimited.  This is primarily used for troubleshooting or pre-run checks')
parser.add_argument('--max_main_packets', type=int, default=0, help='the max number of packets from each pcap in '
                    'main pcaps directory to process. 0=unlimited.  This is primarily used for troubleshooting')
args = parser.parse_args()

# Program Variables #############
debug = args.debug
do_compare = args.compare
do_tcp_check = args.tcp_reset
list_pcap_files = args.list_pcaps
flip_pcaps = args.flip_pcaps
missing_pkts_to_pcap = args.output_pcap
track_time = args.timer
results_dir = args.results_dir
max_pcap1_files = args.max_main_pcaps
max_pcap2_files = args.max_match_pcaps
max_packets_to_compare = args.max_main_packets

# Directory Path, pcap files in this dir will be compared to pcaps in pcap2_dir to
# check if packets from files in pcap1_dir exist in any of pcaps in  pcap2_dir
if flip_pcaps:
    pcap1_dir = args.pcap_dir_match
    pcap2_dir = args.pcap_dir_main
else:
    pcap1_dir = args.pcap_dir_main
    pcap2_dir = args.pcap_dir_match

# Program Initialization ##########
start_time = time.time()
missing_pkts = {}
matched_pkt_keys = set()
total_checked_pkts = 0
total_matched_pkts = 0
first_packet_time = None
last_packet_time = None

# Main() ##########################
chk_pkt = check_pkt_support  # Assign chk_pkt_support() function to a variable

# process pcap dirs for pcap files
files_pcap1 = get_pcap_files(pcap1_dir, max_pcap1_files)
files_pcap2 = get_pcap_files(pcap2_dir, max_pcap2_files)

if not files_pcap1:
    print('No pcap files found in pcap dir 1: Aborting')
    sys.exit(1)

if not files_pcap2:
    print('No pcap files found in pcap dir 2: Aborting')
    sys.exit(1)

print(f'INFO: # files in "main" pcap dir (pcap1): {len(files_pcap1)}')
print(f'INFO: # files in "match" pcap dir (pcap2): {len(files_pcap2)}')

# Just informational, display  the files found in each defined pcap directory
if list_pcap_files:
    print(f'############ files in pcap1 dir {pcap1_dir} ###############')
    for f in files_pcap1:
        print(f'  {f}')
        print(f'  total: {len(f)}')

    print(f'########### files in pcap2 dir {pcap2_dir} ################')
    for f in files_pcap2:
        print(f'  {f}')
        print(f'  total: {len(f)}')

# Start processing of each file in pcap_dir1 ########################################
for p1_count, f1 in enumerate(files_pcap1):
    print(f'###P1# ({p1_count +1} of {len(files_pcap1)}) Reading {f1} to memory. ', end='')
    # Use scapy rdpcap() to read pcap (or pcapng) to memory as scapy.plist.PacketList
    try:
        pkt_list1 = rdpcap(f'{pcap1_dir}/{f1}')
    except Exception as e:
        print(f'Error: Unable to read file {f1} as pcap: Aborting')
        print(e)
        sys.exit(1)

    # Pass the check_pkt_support function to the scapy PacketList filter function to
    # filter for supported packet types then re-assign pkt_list1 with the results
    print(f'Number of packets: {len(pkt_list1)}')
    pkt_list1 = pkt_list1.filter(chk_pkt)
    total_checked_pkts += len(pkt_list1)

    # Save some packet timestamps for later analysis
    if p1_count == 0:
        first_packet_time = pkt_list1[0].time

    if p1_count == len(files_pcap1):
        last_packet_time = pkt_list1[p1_count].time

    # If tracking missing packets, we make a copy of all packets to new dict()
    # will then subtract matched packets from this dict().
    # This is not efficient for memory or cpu, but we need to create a key
    # from a list with no keys to track the packet and remove later if needed
    if missing_pkts_to_pcap and do_compare:
        for i, p in enumerate(pkt_list1):
            # have to give a unique key for each packet from each main (p1) file
            missing_pkts[f'{p1_count}:{i}'] = p

    # To optimize for speed, adding relevant packet data to a dict as a string in as key in dict
    # with the original packet list index as the value. (easier/faster to compare dictionary keys vs values)
    p1_dict = pkt_list_to_dict(pkt_list1)

    # Start process of each file in pcap_dir2 ########################################
    # Compare pcap from dir1 to every pcap from dir2 (up to max defined # of files to compare)
    for p2_count, f2 in enumerate(files_pcap2):
        matched_pkts_per_p2 = 0
        print(f'  ##P2# ({p2_count +1} of {len(files_pcap2)}) Reading {f2} to memory. ', end='')
        # Use scapy redcap() to read pcap (or pcapng) to memory as scapy.plist.PacketList
        try:
            pkt_list2 = rdpcap(f'{pcap2_dir}/{f2}')
        except Exception as e:
            print(f'Error: Unable to read file {f2} as pcap: Aborting')
            print(e)
            sys.exit(1)

        print(f'Number of packets: {len(pkt_list2)}')

        # pass the check_pkt_support function to the scapy PacketList filter function to
        # filter for supported packet types then re-assign pkt_list1 with the re
        pkt_list2 = pkt_list2.filter(chk_pkt)

        # To optimize for speed, adding relevant packet data to a dict as a string
        # We should then be able to compare sets of packets from both pcaps much faster
        p2_dict = pkt_list_to_dict(pkt_list2)

        # Recover some memory
        pkt_list2 = ''

        # Start to check if packets in pcap file from dir1 are in any pcap files in dir2
        if do_compare:
            print(f'    ## Compare packets in {f1} to {f2}:')

            # For before after comparison of main p1 packet dict() to see if it decrements (debugging only)
            if debug:
                print(f'      p1_dict before compare: {len(p1_dict)}')

            # Make a copy of p1_dict rather than x=p1_dict because = is just a reference, and we intend to
            # Modify the original during the for loop iterations which would otherwise be illegal
            tmp_p1_dict = dict(p1_dict)

            # Remove any matched packets from the current "main" pcap dict() so that we do not try to
            # match a matched packet again.
            for k in tmp_p1_dict:
                if k in p2_dict:
                    # keep track of all packets matched
                    matched_pkt_keys.add(f'{p1_count}:{tmp_p1_dict[k]}')
                    total_matched_pkts += 1
                    matched_pkts_per_p2 += 1
                    # Delete matched packets from original packet list to avoid further checking for this pkt
                    del p1_dict[k]

            print(f'      Valid Packets to Check: {len(tmp_p1_dict)}')
            print(f'      Number of matched packets this run: {matched_pkts_per_p2}')
            print(f'      Total matched packets for all runs: {total_matched_pkts}')

            # check modifications that have been made to the "main" p1_dict (verifying packets are removed if matched)
            if debug:
                print(f'      p1_dict after compare: {len(p1_dict)}')

        # If all packets have been matched we can break from this loop iterations
        # for current main file and get next pcap1
        if len(p1_dict) == 0:
            if debug:
                print('####### No packets left in current p1 packet list, move to next p1')
            break


# Print total number of matched and missing packets from total of all files in pcap_dir1 (or pcap_dir2 if flipped)
print('#############################################')
if do_compare:
    print(f'Total Packets Checked: {total_checked_pkts}')
    print(f'Total Matched Packets: {total_matched_pkts}')
    print(f'Total Missing Packets: {total_checked_pkts - total_matched_pkts}')
    print(f'Percent Packet Drop: {round(((total_checked_pkts - total_matched_pkts) / total_checked_pkts) * 100, 12)}%')
print('#############################################')
# Print out total run time
if track_time:
    print(f'Run time: {str(datetime.timedelta(seconds=int(time.time()) - int(start_time)))}')

# Write missing packets to pcap (if enabled)
if missing_pkts_to_pcap and do_compare:
    # If enabled, write missing packets to new pcap file
    now = datetime.datetime.now()
    out_pkts = []

    # Remove all matched packets from the missing pkt list dict()
    for i in matched_pkt_keys:
        del missing_pkts[i]

    if len(missing_pkts) > 0:
        # Copy all pkts (val) in missing_pkts_list to out_pkts list (for write to pcap)
        # basically converting missing pkts from dict() to list()
        for i in missing_pkts:
            out_pkts.append(missing_pkts[i])

        print(f'Start writing missing Packets ({len(missing_pkts)}) to PCAP: '
              f'{results_dir}/missing_pkts-{now.strftime("%Y-%m-%d_%H-%M")}.pcap')

        try:
            wrpcap(f'{results_dir}/missing_pkts-{now.strftime("%Y-%m-%d_%H-%M")}.pcap', out_pkts)
        except Exception as e:
            print(e)
            print(f'Error: Unable to write to pcap file in dir: {results_dir}')
        else:
            print(f'Success writing pcap: '
                  f'{results_dir}/missing_pkts-{now.strftime("%Y-%m-%d_%H-%M")}.pcap')
    else:
        print('No missing packets to write to pcap: Skipping')

print(f'first packet timestamp: {first_packet_time}')
print(f'last packet timestamp: {last_packet_time}')
