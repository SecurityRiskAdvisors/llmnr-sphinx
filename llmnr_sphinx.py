#!/usr/bin/env python

from scapy.all import *
import configparser
import random
import re
import threading
import time
import syslog
import json
import argparse
import os

# Set up script constants
SENDING_DELAY_RATIO = .2
TIMEOUT_MIN = 5

# Set up scapy constants
Ether.payload_guess = [({"type": 0x800}, IP)]
IP.payload_guess = [({"frag": 0, "proto": 0x11}, UDP)]

# Set up syslog
LOG_DEFAULT = 0
syslog.openlog("llmnr-sphinx", LOG_DEFAULT, syslog.LOG_USER)


def randomword(length=6):
    if length < 1:
        length = 1
        pass

    letters = "abcdefjhijklmnopqrstuvwxyz"
    return "".join(random.choice(letters) for i in range(length))


class SnifferThread(threading.Thread):
    def __init__(
        self, query_data, filter="udp and port 5355", timeout=5, interface=None
    ):
        threading.Thread.__init__(self)
        self.query_data = query_data
        # This filter keeps it from being overly burdened by incoming packets
        self.filter = filter
        self.timeout = timeout
        self.interface = interface

    def run(self):
        syslog.syslog(
            syslog.LOG_DEBUG,
            "Starting listener on interface %s with a %s second timeout."
            % (self.interface, self.timeout),
        )
        response = sniff(
            iface=self.interface,
            prn=self.callback_llmnr,
            filter=self.filter,
            lfilter=self.lfilter_llmnr,
            timeout=self.timeout,
        )
        pass

    def lfilter_llmnr(self, packet):
        return (
            LLMNRResponse in packet
            and packet[LLMNRResponse].id == self.query_data["id"]
            and packet[LLMNRResponse].an.rdata not in self.query_data["expected_ans"]
        )

    def callback_llmnr(self, packet):
        self.query_data["anomalous_packets"].append(
            {
                "src_mac": packet[Ether].src,
                "src_ip": packet[IP].src,
                "name": packet[LLMNRResponse].an.rrname.decode(),
                "ans": packet[LLMNRResponse].an.rdata,
                "id": packet[LLMNRResponse].id,
            }
        )
        return

    pass


def parse_config_interfaces(interface_name):

    # Check to make sure the interface exists and can be used
    if (interface_name == "" or interface_name == "None"):
        return None
    else:
        try:
            conf.L3socket(iface=interface_name)
            return_value = interface_name
            return interface_name
            pass
        except OSError:
            raise ValueError(
                "Interface: %s does not exist" % (interface_name)
            ) from None
        pass
    pass


def read_file(config_file, max_size=1 * 2 ** 20):
    file_size = os.path.getsize(config_file)
    if file_size < max_size:
        with open(config_file) as fp_config_file:
            config_contents = fp_config_file.read(file_size)
            eof = fp_config_file.read(1)
            pass

        if len(eof) > 0:
            raise ValueError(
                "File changed after program execution, please ensure file is not corrupted"
            )
        return config_contents
        pass
    else:
        raise ValueError(
            "Config file is larger than 1MB, please ensure that the file is correctly formatted"
        )
    pass


def parse_parameters(config_file_contents):

    config = configparser.ConfigParser()

    config.read_string(config_file_contents)

    core_config = {}
    try:
        core_config["sending_delay"] = config["General"].getint("sending_delay")
    except ValueError:
        raise ValueError("sending_delay needs to be an integer")

    try:
        core_config["timeout"] = config["General"].getint("timeout")
        if core_config["timeout"] == None:
            core_config["timeout"] = int(
                core_config["sending_delay"] * SENDING_DELAY_RATIO
            )
            if core_config["timeout"] < TIMEOUT_MIN:
                core_config["timeout"] = TIMEOUT_MIN
    except ValueError:
        raise ValueError("timeout needs to be an integer")

    if core_config["timeout"] > core_config["sending_delay"]:
        raise ValueError("timeout needs to be smaller than sending delay")

    if config["General"].get("output") == "syslog":
        core_config["output"] = config["General"].get("output")
    else:
        raise ValueError("output must be syslog")

    if config["General"].get("interface") is not None:
        core_config["send_interface"] = parse_config_interfaces(
            config["General"].get("interface")
        )
        core_config["listen_interface"] = core_config["send_interface"]
        if (
            config["General"].get("send_interface")
            or config["General"].get("listen_interface")
        ) is not None:
            raise ValueError("Either set interface or listen_interface/send_interface.")
        pass
    else:
        if config["General"].get("send_interface") is not None:
            core_config["send_interface"] = parse_config_interfaces(
                config["General"].get("send_interface")
            )
            pass
        if config["General"].get("listen_interface") is not None:
            core_config["listen_interface"] = parse_config_interfaces(
                config["General"].get("listen_interface")
            )
            pass
    if (
        config["General"].get("listen_interface")
        or config["General"].get("send_interface")
        or config["General"].get("interface")
    ) is None:
        core_config["send_interface"] = None
        core_config["listen_interface"] = None
    pass

    rounds = ["round-1", "round-2"]

    core_config["queries"] = {}

    for cur_round in rounds:
        core_config["queries"][cur_round] = []
        try:
            if len(config[cur_round]) == 0:
                raise ValueError("%s does not have any entries" % (cur_round))
            for key in config[cur_round]:
                answer_list = []
                if config[cur_round][key] == "None":
                    answer_list = [None]
                elif (
                    re.fullmatch(
                        "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} ?)+",
                        config[cur_round][key],
                    )
                    is not None
                ):
                    answer_list = config[cur_round][key].split()
                    pass
                else:
                    raise ValueError(
                        "%s needs to have an IP address, space separated IP address list, or None. Current Value: %s"
                        % (key, config[cur_round][key])
                    )
                    pass

                core_config["queries"][cur_round].append(
                    {
                        "id": None,
                        "qname": key,
                        "expected_ans": answer_list,
                        "anomalous_packets": [],
                    }
                )
                pass
        except KeyError:
            raise ValueError("The %s section is missing from the ini" % (cur_round))
    return core_config


def parse_config(config_file="/etc/llmnr_sphinx/config.ini"):

    try:
        config_file_contents = read_file(config_file)
    except OSError as e:
        raise ValueError("Could not parse config file. Error: %s" % (str(e)))

    config = parse_parameters(config_file_contents)
    syslog.syslog(
        syslog.LOG_DEBUG, "Successfully parsed ini file at %s" % (config_file)
    )
    return config


# There's no point in doing a random-int on a single size list. Have two functions to break out what work to do.
def get_rand_from_list(arr):
    return arr[random.randint(0, len(arr) - 1)]


def get_single_value(arr):
    return arr[0]


def construct_query(query_data):
    # If the query needs to be random, create a random string each time it is sent out.
    # However, store it with the key $random for future iterations and for logging
    if "$random" in query_data["qname"]:
        name = randomword()
        query_data["qname"] = "$random:%s" % (name)
        pass
    else:
        name = query_data["qname"]
        pass

    # ID needs to be p-random. Not trying too hard here.
    query_data["id"] = random.getrandbits(16)

    return (
        Ether()
        / IP(dst="224.0.0.252")
        / UDP()
        / LLMNRQuery(id=query_data["id"], qd=DNSQR(qname=name))
    )


def run_query(
    query_data, timeout=TIMEOUT_MIN, send_interface=None, listen_interface=None
):
    query = construct_query(query_data)
    sniffer = SnifferThread(
        query_data=query_data, timeout=timeout, interface=listen_interface
    )
    sniffer.start()
    ## Sleep for a bit to let the sniffer get set up
    time.sleep(1)
    sendp(query, iface=send_interface, verbose=0)
    syslog.syslog(
        syslog.LOG_DEBUG,
        "Sent query %s on interface %s with expected answer: %s"
        % (
            query_data["qname"],
            send_interface,
            ", ".join(map(str, query_data["expected_ans"])),
        ),
    )
    sniffer.join()
    pass


def generate_report(spoofed_results):
    # Generate results, critical if detected, alert if confirmed
    for src_mac in spoofed_results:
        confirmation_strength = "detected"
        priority = syslog.LOG_CRIT
        spoofed_result = spoofed_results[src_mac]
        if len(spoofed_result["responses"]) > 1:
            confirmation_strength = "confirmed"
            priority = syslog.LOG_ALERT
            pass
        pass

        syslog.syslog(
            priority,
            "LLMNR Spoofing %s from %s (%s). Query Data: %s."
            % (
                confirmation_strength,
                src_mac,
                ", ".join(spoofed_result["src_ip"]),
                json.dumps(spoofed_result["responses"]),
            ),
        )
        #print(
        #    "(to syslog: %s) LLMNR Spoofing %s from %s (%s). Query Data: %s."
        #    % (
        #        priority,
        #        confirmation_strength,
        #        src_mac,
        #        ", ".join(spoofed_result["src_ip"]),
        #        json.dumps(spoofed_result["responses"]),
        #    )
        #)
        # CRITICAL: LLMNR Spoofing Confirmed from 84:7b:eb:b5:4d:de
        # {'src_ip': {'192.168.89.130'}, 'responses': [{'qname': '$random:ojluel', 'name': 'ojluel.', 'ans': '192.168.89.130'}, {'qname': '_kerberos', 'name': '_kerberos.', 'ans': '192.168.89.130'}]}
        pass
    pass


def sleep_until(delay):
    syslog.syslog(syslog.LOG_DEBUG, "Starting %s second delay" % (delay))
    time.sleep(delay)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="A service that detects llmnr spoofers on a network"
    )
    parser.add_argument(
        "--config",
        "-c",
        default="/etc/llmnr_sphinx/config.ini",
        help="path to config file. Defaults to: /etc/llmnr_sphinx/config.ini",
    )
    args = parser.parse_args()

    core_config = parse_config(config_file=args.config)

    round_1 = core_config["queries"]["round-1"]
    round_2 = core_config["queries"]["round-2"]

    # Use a single function instead of always checking the size
    # This seems dirty, should be cleaned up
    if len(round_1) > 1:
        get_query_data = get_rand_from_list
        pass
    else:
        get_query_data = get_single_value
        pass

    if len(round_2) > 1:
        get_query_data_2 = get_rand_from_list
        pass
    else:
        get_query_data_2 = get_single_value
        pass

    query_data_round_1 = {}
    query_data_round_2 = {}

    query_counter = 0

    while True:
        syslog.syslog(
            syslog.LOG_NOTICE,
            "Heartbeat message, number of queries %s" % (query_counter),
        )
        query_counter += 1
        # Handling Round 1 here
        query_data_round_1 = get_query_data(round_1)
        run_query(
            query_data=query_data_round_1,
            timeout=core_config["timeout"],
            send_interface=core_config["send_interface"],
            listen_interface=core_config["listen_interface"],
        )
        if len(query_data_round_1["anomalous_packets"]) > 0:

            syslog.syslog(
                syslog.LOG_DEBUG,
                "Recieved %s anomalous %s, starting round 2"
                % (
                    len(query_data_round_1["anomalous_packets"]),
                    "packet"
                    if (len(query_data_round_1["anomalous_packets"]) == 1)
                    else "packets",
                ),
            )
            # anomalous packets found let's check
            query_data_round_2 = get_query_data_2(round_2)
            run_query(
                query_data=query_data_round_2,
                timeout=core_config["timeout"],
                send_interface=core_config["send_interface"],
                listen_interface=core_config["listen_interface"],
            )
            syslog.syslog(
                syslog.LOG_DEBUG,
                "Recieved %s anomalous %s in round 2, starting reporting."
                % (
                    len(query_data_round_2["anomalous_packets"]),
                    "packet"
                    if (len(query_data_round_2["anomalous_packets"]) == 1)
                    else "packets",
                ),
            )
            pass

        # Clean up data a bit, we care about src_mac primarily so we'll group by that
        spoofed_results = {}
        if len(query_data_round_1["anomalous_packets"]) > 0:
            for anomalous_packet in query_data_round_1["anomalous_packets"]:
                spoofed_results[anomalous_packet["src_mac"]] = {
                    "src_ip": {anomalous_packet["src_ip"]},
                    "responses": [
                        {
                            "qname": query_data_round_1["qname"],
                            "name": anomalous_packet["name"],
                            "ans": anomalous_packet["ans"],
                        }
                    ],
                }
                pass

            # Add round_2 only if it exists
            try:
                for anomalous_packet in query_data_round_2["anomalous_packets"]:
                    spoofed_results[anomalous_packet["src_mac"]]["src_ip"].add(
                        anomalous_packet["src_ip"]
                    )
                    spoofed_results[anomalous_packet["src_mac"]]["responses"].append(
                        {
                            "qname": query_data_round_2["qname"],
                            "name": anomalous_packet["name"],
                            "ans": anomalous_packet["ans"],
                        }
                    )
                    pass
                pass
            except KeyError:
                pass

        # If both rounds don't exist then clear whatever you can.
        try:
            query_data_round_1["anomalous_packets"].clear()
            pass
        except KeyError:
            pass
        try:
            query_data_round_2["anomalous_packets"].clear()
            pass
        except KeyError:
            pass

        generate_report(spoofed_results)

        sleep_until(core_config["sending_delay"])
        pass
