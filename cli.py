import argparse


def get_parser():
    parser = argparse.ArgumentParser(description="A simple network scanner")
    parser.add_argument("--interface", help="Which network interface to start the scan on. Ex: en0")
