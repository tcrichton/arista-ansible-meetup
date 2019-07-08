#!/usr/bin/env python3
import sys
import logging
import argparse
from pybatfish.client.commands import *
from pybatfish.question.question import load_questions, list_questions
from pybatfish.question import bfq
from pybatfish.datamodel.flow import HeaderConstraints as header


def test_controlplane(isFailed):
    # Define a list of Spine switches
    spines = set(bfq.nodeProperties(nodes='spine.*').answer().frame()['Node'])
    logging.info("Progress: Analyzing control plane properties")

    # Get all BGP session status for leaf nodes
    bgp = bfq.bgpSessionStatus(nodes='leaf.*').answer().frame()

    # All leaves should have at least one peering with each spine
    violators = bgp.groupby('Node').filter(lambda x: set(x['Remote_Node']).difference(spines) != set([]))
    if len(violators) > 0:
        logging.error("Found leaves that do not have at least one peering to each spine")
        logging.error(violators[['Node', 'Remote_Node']])
        isFailed = True
    else:
        logging.info("All leaves have at least one peering with each spine")

    # All leaves should only peer with spines
    non_spines = bgp[~bgp['Remote_Node'].str.contains('spine', na=False)]
    if len(non_spines) > 0:
        logging.error("Leaves do not only peer with spines")
        logging.error(non_spines[['Node', 'Remote_Node']])
        isFailed = True
    else:
        logging.info("Leaves only peer with spines")

    return isFailed

def test_config_sanity(isFailed):
    logging.info("Progress: Searching for unused and undefined data structures")
    # Find all undefined data structures
    undefined = bfq.undefinedReferences().answer().frame()
    if len(undefined) >  0:
        logging.error("Found undefined data structures")
        logging.error(undefined)
        isFailed = True
    else:
        logging.info("No undefined data structures found")

    # Find all unused data structures
    unused = bfq.unusedStructures().answer().frame()
    if len(unused) >  0:
        logging.error("Found unused data structures")
        logging.error(unused)
        isFailed = True
    else:
        logging.info("No unused data structures found")

    return isFailed


def main():
    parser = argparse.ArgumentParser(description="Script to test network configs with batfish")
    parser.add_argument("--batfish_server", help="IP/host of the batfish server", default='localhost',type=str)
    parser.add_argument("--candidate", help='Path to directory containing candidate device configuration folder', default='./candidate', type=str)
    parser.add_argument("--log", help='Path to logging file', default='batfish.log', type=str)
    OPTIONS = parser.parse_args()


    logging.info('=> Batfish server is running on: %s' , str(OPTIONS.batfish_server))
    bf_session.host = OPTIONS.batfish_server

    # Configure logging for log file if defined.
    if OPTIONS.log:
        logging.basicConfig(filename=OPTIONS.log, format='%(levelname)s: %(message)s', level=logging.INFO)
        console = logging.StreamHandler()
        console.setLevel(logging.ERROR)
        logging.getLogger('').addHandler(console)

    # Initialize BATFISH session
    # Batfish server must be running on a container
    # docker run -p 8888:8888 -p 9997:9997 -p 9996:9996 batfish/allinone
    load_questions()
    bf_init_snapshot(OPTIONS.candidate, name='candidate')

    bf_set_snapshot('candidate')
    csFailed = test_config_sanity(False)
    logging.info('=> csFailed status: %s' , str(csFailed))
    cpFailed = test_controlplane(False)
    logging.info('=> cpFailed status: %s' , str(cpFailed))

    if csFailed or cpFailed:
        return 1
    else:
        return 0

if __name__ == '__main__':
    sys.exit(main())
