"""
From: Nick Petersen
Email: 77npete@gmail.com
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
parser.add_argument('-l', '--list_pcaps', type=bool, default=False, help='print list of pcaps to process to console')
parser.add_argument('-T', '--timer', type=bool, default=True, help='print time taken to execute')
parser.add_argument('--pcap_dir', type=str, required=True,
                    help='Path relative/absolute to the directory containing pcaps to check for missing packets')
parser.add_argument('-r', '--results_dir', type=str, default='./', help='directory path for any output incl. pcaps')
parser.add_argument('--max_pcaps', type=int, default=0, help='The max number of pcaps from "main" pcap '
                    'directory to process. 0=unlimited. This is primarily for troubleshooting or pre-run checks')
parser.add_argument('--max_packets', type=int, default=0, help='the max number of packets from each pcap in '
                    'main pcaps directory to process. 0=unlimited.  This is primarily used for troubleshooting')
args = parser.parse_args()

# Program Variables #############
debug = args.debug
do_compare = args.compare
list_pcap_files = args.list_pcaps
track_time = args.timer
pcap_dir = args.pcap_dir
results_dir = args.results_dir
max_pcap_files = args.max_pcaps
max_packets_to_compare = args.max_packets
output_pcap = args.output_pcap

# Program Initialization ##########
start_time = time.time()
total_pkt_checked = 0
tcp_pkt_count = 0
udp_pkt_count = 0
icmp_pkt_count = 0
icmpv6_pkt_count = 0
tcp_flag_syn = 0
tcp_flag_fin = 0
tcp_flag_psh = 0
tcp_flag_rst = 0
tcp_flag_ack = 0
tcp_flag_syn_ack = 0
tcp_flag_fin_ack = 0
tcp_flag_psh_ack = 0
tcp_flag_other = 0
tcp_flag_sum = 0
tcp_reset_pkt_list = []
tcp_retrans_pkt_list = []

tcp_other_list = []

# Main() ##########################
files_pcap = os.listdir(pcap_dir)

# Check input files
if len(files_pcap) < 1:
    print('No pcap files found in pcap dir: Aborting')
    sys.exit(1)

for f in files_pcap:
    if pathlib.Path(f).suffix not in ['.pcap']:
        print(f'Notice: file "{f}: in pcap_dir file extension not ".pcap" .out: SKIPPING')
        files_pcap.remove(f)

print(f'INFO: # files in pcap dir (pcap1): {len(files_pcap)}')

# Just informational, display  the files found in each defined pcap directory
if list_pcap_files:
    print(f'############ files in pcap1 dir {pcap_dir} ###############')
    for f in files_pcap:
        print(f'  {f}')
        print(f'  total: {len(f)}')


# Start processing of each file in pcap_dir1 ########################################
for f_count, f1 in enumerate(files_pcap):

    print(f'## ({f_count +1} of {len(files_pcap)}) Reading {f1} to memory. ', end='')
    # Use scapy rdpcap() to read pcap (or pcapng) to memory as scapy.plist.PacketList
    try:
        pkt_list = rdpcap(f'{pcap_dir}/{f1}')
    except Exception as e:
        print(f'Error: Unable to read file {f1} as pcap: Aborting')
        sys.exit(1)

    print(f'Number of packets: {len(pkt_list)}')

    for pkt in pkt_list:
        if check_packet_attributes(pkt):
            total_pkt_checked += 1
            match pkt[Ether].proto:
                case 1:
                    icmp_pkt_count += 1
                case 6:
                    tcp_pkt_count += 1

                    match pkt['TCP'].flags:
                        case 0x001:
                            tcp_flag_fin += 1
                            tcp_flag_sum += 1
                        case 0x002:
                            tcp_flag_syn += 1
                            tcp_flag_sum += 1
                        case 0x004:
                            tcp_flag_rst += 1
                            tcp_flag_sum += 1
                        case 0x008:
                            tcp_flag_psh += 1
                            tcp_flag_sum += 1
                        case 0x010:
                            tcp_flag_ack += 1
                            tcp_flag_sum += 1
                        case 0x011:
                            tcp_flag_fin_ack += 1
                            tcp_flag_sum += 1
                        case 0x012:
                            tcp_flag_syn_ack += 1
                            tcp_flag_sum += 1
                        case 0x018:
                            tcp_flag_psh_ack += 1
                            tcp_flag_sum += 1
                        case _:
                            tcp_flag_other += 1
                            tcp_flag_sum += 1
                            tcp_other_list.append(pkt)

                case 17:
                    udp_pkt_count += 1
                case 58:
                    icmpv6_pkt_count += 1

    # Stop after max_pcap_files to process is reached
    if (f_count + 1) >= max_pcap_files > 0:
        print(f'Max pcap files reached: {max_pcap_files} (set by --max_pcap_files) limit reached: Stopping')
        break


print('##################')
print(f'Total IP Packets.......{total_pkt_checked}')
print(f'Total TCP Packets......{tcp_pkt_count}')
print(f'  TCP SYN.................{tcp_flag_syn}')
print(f'  TCP SYN+ACK.............{tcp_flag_syn_ack}')
print(f'  TCP FIN.................{tcp_flag_fin}')
print(f'  TCP FIN+ACK.............{tcp_flag_fin_ack}')
print(f'  TCP ACK.................{tcp_flag_ack}')
print(f'  TCP RST.................{tcp_flag_rst}')
print(f'  TCP PSH.................{tcp_flag_psh}')
print(f'  TCP PSH+ACK.............{tcp_flag_psh_ack}')
print(f'  TCP Other...............{tcp_flag_other}')
#print(f'  Total Flags.............{tcp_flag_sum}')
print(f'Total UDP Packets......{udp_pkt_count}')
print(f'Total ICMP Packets.....{icmp_pkt_count}')
print(f'Total ICMPv6 Packets...{icmpv6_pkt_count}')
print('##################')

if track_time:
    print(f'Run time: {str(datetime.timedelta(seconds=int(time.time()) - int(start_time)))}')

if output_pcap:
    pcap_out = tcp_other_list
    # If enabled, write missing packets to new pcap file
    if not len(pcap_out) > 0:
        print('No missing packets to write to pcap: skipping')
    else:
        now = datetime.datetime.now()

        print(f'Start writing missing Packets PCAP: '
              f'{results_dir}/stats_pcap-{now.strftime("%Y-%m-%d_%H-%M")}.pcap')
        try:
            wrpcap(f'{results_dir}/stats_pcap-{now.strftime("%Y-%m-%d_%H-%M")}.pcap', pcap_out)
        except Exception as e:
            print(e)
            print(f'Error: Unable to write to pcap file in dir: {results_dir}')
        else:
            print(f'Success writing pcap: '
                  f'{results_dir}/stats_pcap-{now.strftime("%Y-%m-%d_%H-%M")}.pcap')
                                                                                                                                                                                                                                                                                                                                                                                                              # wrpcap(f'{results_dir}/missing_packets.pcap', missing_packets)