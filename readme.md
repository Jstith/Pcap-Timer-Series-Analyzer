# PCAP Time Series Analyzer

By: _Jstith_

## About

I was doing a CTF challenge recently, and I found the need to analyze large collections of flows coming in and out of pcaps to look for beaconing traffic to a C2 server. I tried to use [Arkmine](https://arkime.com/) and [RITA](https://github.com/activecm/rita), but Arkmine's graphics were focused on large volumes of valid update traffic, and RITA didn't really find anything of value, either.

So, I worked on a script that parses a PCAP and sorts by source IP to destination IP, and pulls out some simple statistics about each source / destination pair:
- Number of packets
- Total duration of the connection
- Average time between transmission of packets
- Standard Deviation between transmission of packets

The idea behind these statistics is that C2 beaconing traffic would, in theory:
- Have a long total duration
- Have a decent number of packets (but probably not a huge number)
- Have a longer average time between packet transmission
- Have a low standard deviation for transmission times

In order to generate these numbers at scale, I used `scapy` to pull out the relevant details from the PCAP, then converted the data into a `Pandas` dataframe. Once in dataframe format, I used slicing and indexing to generate the statistics quickly. The only real runtime issue I have is the time it takes to load the PCAP.

## Usage

This tool uses `scapy` and `pandas` for core functionality, with `rich-progress` to visualize how quickly the parsing takes place.

```
pip install -r requirements.txt
```

To use, simply run the python script and feed in your pcap file with `-r`.

```
python3 PCTSAnalyzer.py -r {file.pcap}
```

## Future Goals

- Implement IP:Port to IP:Port statistics
- Group packets into flows or streams, so the average time between transmission and std dev doesn't get thrown off by one large continuous session
- Add some kind of deterministic formula to determine "most likely" candidates for C2
- Improve load speed for larger pcaps
