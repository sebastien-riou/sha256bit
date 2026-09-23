import argparse
import logging

from sha256bit import Sha224bit, Sha256bit
from sha256bit.utils import ba, hexstr

ALGOS = {'sha256': Sha256bit, 'sha224': Sha224bit}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='sha256bit.cli')
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='WARNING', choices=levels)
    parser.add_argument('--algo', default='sha256', choices=ALGOS.keys())
    parser.add_argument('--bit-length', help='Bit length of message', default=None, type=int)
    parser.add_argument('message', nargs=1, help='Message to hash', type=str)
    args = parser.parse_args()
    logging.basicConfig(format='%(message)s', level=args.log_level)
    msg = ba(args.message[0])
    digest = ALGOS[args.algo](msg, bitlen=args.bit_length).digest()
    print(hexstr(digest))
