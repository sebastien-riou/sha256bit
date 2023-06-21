import argparse
import logging

from pysatl import Utils

from sha256bit import Sha256bit

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='sha256bit.cli')
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='WARNING', choices=levels)
    parser.add_argument('--bit-length', help='Bit length of message', default=None, type=int)
    parser.add_argument('message', nargs=1, help='Message to hash', type=str)
    args = parser.parse_args()
    logging.basicConfig(format='%(message)s', level=args.log_level)
    msg = Utils.ba(args.message[0])
    digest = Sha256bit(msg, bitlen=args.bit_length).digest()
    print(Utils.hexstr(digest))
