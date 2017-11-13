import json
import configparser

from scapy.all import PcapReader
from stuckbucks_captive_portal_checker import StuckbucksCaptivePortalChecker

config = configparser.ConfigParser()
config.read('config.ini')


if __name__ == '__main__':
    scpc = StuckbucksCaptivePortalChecker()

    # Parsing pcap file and checking packet one by one
    with PcapReader(config['PATH']['PCAP_INPUT_PATH']) as pcap_reader:
        for cnt, pkt in enumerate(pcap_reader):
            for capture in scpc.current_captures:
                getattr(scpc, capture)(pkt, cnt)

    # Saving result into json format
    with open(config['PATH']['JSON_OUTPUT_PATH'], 'w') as fptr:
        json.dump(scpc.captured_pkt_list, fptr, sort_keys=True, indent=4, separators=(',', ': '))
