Starbucks Captive Portal Checker
=================================

A checker for making sure the process of starbucks captive portal.

This is a hackathon project of `IETF 100 Hackathon <https://www.ietf.org/registration/MeetingWiki/wiki/100hackathon>`_.

Author: aoimidori27@gmail.com note351@hotmail.com

Documentation
-------------

`Presentation <https://github.com/capport-wg/wg-materials/blob/master/ietf100/hackathon_capport-quick-checker.pdf>`_

How to run this project?
------------------------

**Stage1 - Get .pcap file**

1. Go to Starbucks Cafe
2. Turn off your wifi, close the browser
3. Starting to capture packets by toos(such as wireshark, tcpdump) on wifi interface
4. Turn on your wifi
5. Open browser
6. Create one tab in the browser and click access wifi
7. Access any website
8. Stop capturing packets, and save the .pcap file

 
**Stage2 - Run checker**

0. Make sure the environment

    * Language: python3.6
    * Operating System: MacOS

1. Clone this project to your local machine

.. code-block:: shell

    $ git clone git@github.com:note35/starbucks_captive_portal_checker.git
    $ cd starbucks_captive_portal_checker

2. Install prerequisite

.. code-block:: shell

    $ brew install https://raw.githubusercontent.com/secdev/scapy/master/.travis/pylibpcap.rb

3. Create virtual environment

.. code-block:: shell

    $ virtualenv -p /usr/local/bin/python3.6 env3
    $ . env3/bin/activate
    $ pip3 install -r requirement.txt

4. Set path config in config.ini

.. code-block:: python

    [PATH]
    PCAP_INPUT_PATH = example.pcap
    JSON_OUTPUT_PATH = example.json

5. Run checker

.. code-block:: shell

    python3.6 checker.py

Explanation
-----------

**FSM flow**

    DHCP -> HTTP302 -> Change Cipher Spec -> HTTP200


**DHCP example:**

.. code-block:: javascript

    {
        "cnt": 50,
        "host address": "10.4.150.35",
        "protocol": "DHCP",
        "time": 1510450337.902647
    }


**HTTP example:**

.. code-block:: javascript

    {
        "cnt": 512,
        "dst": "10.4.150.35",
        "protocol": "HTTP",
        "ret_code": 302,
        "time": 1510450379.816324
    }

**HTTPS example:**

.. code-block:: javascript

    {
        "cnt": 627,
        "content_type": "Change Cipher Spec",
        "handshake_type": "Client Hello",
        "protocol": "HTTPS",
        "time": 1510450380.62389
    }
