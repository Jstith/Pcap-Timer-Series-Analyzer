from rich.progress import Progress
from scapy.all import *
import time
import tracemalloc
import argparse
import pandas as pd
import os
from pathlib import Path
from ipaddress import IPv4Address

def load_file(filename):
    print(f'[*] Loading PCAP {filename} into memory...')
    tracemalloc.start()
    read_start_time = time.time()
    try:
        packets = rdpcap(filename)
    except Scapy_Exception as e:
        print(f'[-] ERROR reading pcap data in "{filename}". Message: {e}')
        print('[*] Exiting...')
        exit()
    mem_size = tracemalloc.get_traced_memory()[1] / 1024 / 1024 # Size in megabytes
    tracemalloc.stop()
    read_end_time = time.time()
    packet_read_time = read_end_time - read_start_time
    print(f'[+] Read {len(packets)} packets into {"{:.2f}".format(mem_size)} MB of ram in {"{:.2f}".format(packet_read_time)} seconds.')
    return packets

def load_args():
    cli_message = 'Time Series PCAP Analyzer (TSPA) is a command-line tool used to analyze statistics in PCAP files to detect patterns fitting the profile of anomalous Command & Control (C2) traffic.'
    parser = argparse.ArgumentParser(description=cli_message)
    parser.add_argument('-r', '--ReadFile', help = "Input PCAP file (*.pcap, *.pcapng)", required=True)
    args = parser.parse_args()

    path = Path(args.ReadFile)
    if not path.exists():
        print(f'[-] ERROR reading file "{args.ReadFile}". Does it exist?')
        print('[*] Exiting...')
        exit()
    return args

def logo():
    print("""
        ______  _____ _____ _____  ___              _
        | ___ \/  __ \_   _/  ___|/ _ \            | |
        | |_/ /| /  \/ | | \ `--./ /_\ \_ __   __ _| |_   _ _______ _ __
        |  __/ | |     | |  `--. \  _  | '_ \ / _` | | | | |_  / _ \ '__|
        | |    | \__/\ | | /\__/ / | | | | | | (_| | | |_| |/ /  __/ |
        \_|     \____/ \_/ \____/\_| |_/_| |_|\__,_|_|\__, /___\___|_|
                                                       __/ |
                                                      |___/
    A tool by @Jstith
    """)
    return

def analyze_packets(packets):

    pcap_start_time = None
    packet_data = []
    for packet in packets:
        if(IP in packet):
            try:
                src_addr = packet[IP].src
                dst_addr = packet[IP].dst
                src_port = packet.sport
                dst_port = packet.dport
                pkt_time = packet.time
                if(pcap_start_time is None):
                    pcap_start_time = pkt_time
                adjusted_time = float(pkt_time - pcap_start_time)
                packet_data.append([adjusted_time, src_addr, src_port, dst_addr, dst_port])
            except AttributeError:
                continue # Some packets don't have ports or IPs, ignore and continue
        else:
            pass
            #text = packet.show(dump=True)
            #print(f'[*] Skipping packet (no IP found)... {text}')

    packet_df = pd.DataFrame(packet_data, columns = ['Adj Time', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port'])
    return packet_df

def analysis_options(packet_df):
    user_inp = -1
    while(user_inp not in ['1', '2', '3', '4']):
        print('\nSelect an analysis Option:')
        print('[*] 1. View Time Series Data')
        print('[*] 2. IP --> IP statistics')
        print('[*] 3. IP:Port --> IP:Port statistics')
        print('[*] 4. Exit Program')
        print('[~] Select Option:', end=' ')
        user_inp = input()

    if(user_inp == '1'):
        print('\n[+] Time Series Data')
        print(packet_df)
    elif(user_inp == '2'):
        print('\n[+] Generating Statistics for IP to IP connection.')
        ip_statistics(packet_df)
    elif(user_inp == '3'):
        print('\n[+] Generating Statistics for IP:Port to IP:Port connections')
    elif(user_inp == '4'):
        print('\n[*] Exiting...')
        exit()

def ip_statistics(packet_df):

    # Remove broadcast traffic
    packet_df = packet_df.loc[packet_df['Dst IP'] != '255.255.255.255']

    # Trying to add a timer
    with Progress() as p:
        steps = packet_df.drop_duplicates(['Src IP', 'Dst IP']).shape[0]
        timer = p.add_task('Correlating Source and Destination IP Addresses...', total=steps)

        conn_dict = dict.fromkeys(packet_df['Src IP'].unique())
        for key in conn_dict.keys():
            conn_dict[key] = {}
            conns_for_src = packet_df[packet_df['Src IP'] == key]
            dsts_for_src = conns_for_src['Dst IP'].unique()
            for dst in dsts_for_src:
                pair_entries = packet_df.loc[(packet_df['Src IP'] == key) & (packet_df['Dst IP'] == dst)]
                conn_dict[key][dst] = pair_entries
                p.advance(timer)

    # Statistics to compute: Number of packet, duration of connections, average interval, standard deviation of connection
    # append to end of each sub dictionary entry, make into its own dataframe at the end

    df_timeseries = pd.DataFrame(columns = ['Src IP', 'Dst IP', 'Avg Interval', 'Std Dev', 'Duration', 'Num Packets'])
    for src,dst_set in conn_dict.items():
        for dst,packets in dst_set.items():
            count = len(packets)
            if(len(packets) == 1):
                duration = 0
                average_interval = 0
                std_dev = 0
            else:
                duration = packets.iloc[-1]['Adj Time'] - packets.iloc[0]['Adj Time']
                df_interval = packets['Adj Time'].diff().dropna()
                average_interval = df_interval.mean()
                if(len(packets) == 2):
                    std_dev = 0
                else:
                    std_dev = df_interval.std()

            # print(f'Count: {count}, Duration: {duration}, Interval {average_interval}, Std: {std_dev}')
            df_timeseries.loc[len(df_timeseries)] = [src, dst, average_interval, std_dev, duration, count]

    # Sort by standard deviation
    df_timeseries = df_timeseries.sort_values(by=['Num Packets'], ascending=False)

    # Options to view and save NEXT
    os.system(f'echo "{df_timeseries.to_string(index=False)}" | less')
    filename = f'output/{time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time()))}-ip-ts.csv'
    df_timeseries.to_csv(filename, index=False)
    print(f'[+] Data saved to {filename}')

if __name__ == '__main__':
    logo()
    args = load_args()
    packets = load_file(args.ReadFile)
    packet_df = analyze_packets(packets)
    while True:
        analysis_options(packet_df)
