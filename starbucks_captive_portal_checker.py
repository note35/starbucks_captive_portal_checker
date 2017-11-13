import codecs
import logging

from scapy.all import IP, DHCP, Raw, TCP


class StarbucksCaptivePortalChecker(object):
    """
        StarbucksCaptivePortalChecker is a tool for checking the process of captive portal in starbucks
        Since the implementation of captive portal in starbucks will be changed in the future
        This code might not work in the near future.

        The presentation can be found in belows link:
        https://github.com/capport-wg/wg-materials/blob/master/ietf100/hackathon_capport-quick-checker.pdf
    """

    def __init__(self):
        self.current_captures = {"dhcp_capture"} #FSM: initial state
        self.captured_pkt_list = {
            "DHCP": [],
            "HTTP": [],
            "HTTPS": [],
        }
        self.is_dhcp_request_sent = False

    def __pkt_capture(self, record, next_state):
        """
            Storing packet into captured_pkt_list[protocol'] + Setting next state
            Args: record -> dict
                  next_state -> set
        """
        self.captured_pkt_list[record['protocol']].append(record)
        self.current_captures = next_state

    def dhcp_capture(self, pkt, cnt):
        """
            Capturing and storing dhcp packet in captured_pkt_list["DHCP"]
            Args: pkt -> scapy:packet
                  cnt -> int
        """
        if pkt.haslayer(DHCP):
            # Before accepting DHCP packet, the source ip of host is 0.0.0.0
            if pkt[IP].src == "0.0.0.0":
                self.is_dhcp_request_sent = True
            # Recording assigned host address from DHCP packet
            # 5 = DHCPAck See: https://technet.microsoft.com/en-us/library/cc959876.aspx
            if self.is_dhcp_request_sent and pkt[DHCP].options[0][1] == 5:
                record = {
                    'cnt': cnt,
                    'protocol': 'DHCP',
                    'time': pkt.time,
                    'host address': pkt[IP].dst, #host address
                }
                self.__pkt_capture(record, {"http_capture", "tls_capture"}) #FSM: checking state

    def http_capture(self, pkt, cnt):
        """
            Capturing and storing http packets in captured_pkt_list["HTTP"]
            Args: pkt -> scapy:packet
                  cnt -> int
        """
        if pkt.haslayer(TCP):
            try:
                record = {
                    'cnt': cnt,
                    'protocol': 'HTTP',
                    'time': pkt.time,
                    'ret_code': StarbucksCaptivePortalChecker.parse_raw_load(codecs.decode(pkt[Raw].load, 'utf-8')),
                    'dst': pkt[IP].dst
                }
                if record['ret_code'] == 200:
                    self.__pkt_capture(record, {}) #FSM: finishing state
                else:
                    self.__pkt_capture(record, self.current_captures)
            except IndexError:
                logging.info('ignore: IndexError: Layer [Raw] not found')
            except UnicodeDecodeError:
                logging.info('ignore: UnicodeDecodeError ... invalid continuation byte')

    def tls_capture(self, pkt, cnt):
        """
            Capturing and storing tls packets in captured_pkt_list["HTTPS"]
            Args: pkt -> scapy:packet
                  cnt -> int
        """
        if pkt.haslayer(TCP) and pkt[TCP].dport == 443:
            try:
                tcp_load = StarbucksCaptivePortalChecker.parse_tcp_load(bytes(pkt[TCP].load))
                record = {
                    'cnt': cnt,
                    'protocol': 'HTTPS',
                    'time': pkt.time,
                    'content_type': tcp_load['content_type'],
                    'handshake_type': tcp_load['handshake_type'],
                }
                self.__pkt_capture(record, self.current_captures)
            except AttributeError:
                logging.info('ignore: AttributeError: load')

    @staticmethod
    def __get_type(code, type_dict):
        try:
            return type_dict[str(code)]
        except KeyError:
            logging.info('{} is not a valid {}'.format(code, type_dict['__type__']))
            return None

    @staticmethod
    def get_tls_content_type(content_type_code):
        """
            Args: bytes
            Return: string
        """
        tls_content_type = {
            '__type__': 'tls',
            '20': 'Change Cipher Spec',
            '21': 'Alert',
            '22': 'Handshake',
            '23': 'Application Data',
        }
        return StarbucksCaptivePortalChecker.__get_type(content_type_code, tls_content_type)

    @staticmethod
    def get_handshake_type(handshake_type_code):
        """
            Args: bytes
            Return: string
        """
        handshake_type = {
            '__type__': 'handshake',
            '1': 'Client Hello',
            '2': 'Server Hello',
            '11': 'Certificate',
            '12': 'Server Key Exchange',
            '14': 'Server Hello Done',
            '16': 'Client Key Exchange',
        }
        return StarbucksCaptivePortalChecker.__get_type(handshake_type_code, handshake_type)

    @staticmethod
    def parse_tcp_load(tcp_load):
        """
            Args: bytes
            Return: dict
        """
        ret = {
            'compressed_length': tcp_load[3]*256 + tcp_load[4],
            'content_type': StarbucksCaptivePortalChecker.get_tls_content_type(tcp_load[0]),
            'handshake_type': StarbucksCaptivePortalChecker.get_handshake_type(tcp_load[5])
        }
        return ret

    @staticmethod
    def parse_raw_load(raw_load):
        """
            Only handle 200, 302 for checking purpose
            Args: pkt[Raw].load
            Return: int or None
        """
        target_dict = {
            '302 Temporarily Moved': 302,
            '200 OK': 200,
        }
        for key, val in target_dict.items():
            if key in raw_load:
                return val
        else:
            return None
