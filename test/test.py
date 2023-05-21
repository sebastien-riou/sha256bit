import hashlib
import re

from pysatl import Utils

from sha256bit import Sha256bit


def block_generator(seed, msg_bitlen):
    l2block = hashlib.sha256(seed).digest()
    l2block += hashlib.sha256(l2block).digest()
    block_bitlen = len(l2block) * 8
    assert block_bitlen == 64 * 8
    bitlen = 0
    while bitlen + block_bitlen < msg_bitlen:
        yield l2block
        bitlen += block_bitlen
        l2block = hashlib.sha256(l2block).digest()
        l2block += hashlib.sha256(l2block).digest()
    # last block
    last_block_bitlen = msg_bitlen % 512
    if 0 != last_block_bitlen:
        last_block_full_bytelen = (last_block_bitlen + 7) // 8
        l2block = bytearray(l2block[0:last_block_full_bytelen])
        assert len(l2block) == last_block_full_bytelen
        mask = 0xFF & (0xFF << (8 - (msg_bitlen % 8)))
        if 0 != mask:
            l2block[-1] &= mask
    yield l2block


def msg_generator(seed, msg_bitlen):
    o = bytearray()
    for b in block_generator(seed, msg_bitlen):
        o += b
    return o


def check_against_hashlib(n_seeds=3, max_length=1024 * 4):
    print('check against hashlib')

    assert hashlib.sha256(b'abc').digest() == Sha256bit(b'abc').digest()

    def check_against_hashlib(seed, msg_bitlen):
        expected = hashlib.sha256()
        dut = Sha256bit()
        for block in block_generator(seed, msg_bitlen):
            # print(Utils.hexstr(block))
            expected.update(block)
            dut.update(block)
        assert expected.digest() == dut.digest()

    for seed_byte in range(0, n_seeds):
        for msg_bitlen in range(0, max_length, 8):
            seed = bytearray([seed_byte])
            check_against_hashlib(seed, msg_bitlen)


def check(msg, bitlen, sig):
    m = Sha256bit()
    if isinstance(msg, str):
        msg = msg.encode('ascii')
    descr = 'msg      = ' + Utils.hexstr(msg) + '\n'
    descr += 'bitlen   = %d\n' % bitlen
    descr += 'expected = ' + sig + '\n'
    try:
        m.update(msg, bitlen=bitlen)
        digest = m.hexdigest()
    except Exception as e:
        print(descr)
        raise e
    err_msg = '\n'
    err_msg += descr
    err_msg += 'digest   = ' + digest + '\n'
    assert digest == sig, err_msg


def check_hardcoded_test_vectors():
    print('check few minimal hardcoded test vectors')

    tests = [
        {
            'msg': '',
            'bitlen': 0,
            'digest': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        },
        {
            'msg': 'a',
            'bitlen': 8,
            'digest': 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb',
        },
        {
            'msg': Utils.ba('00'),
            'bitlen': 1,
            'digest': 'bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375',
        },
        {
            'msg': Utils.ba('80'),
            'bitlen': 2,
            'digest': '18f331f626210ff9bad6995d8cff6e891adba50eb2fdbddcaa921221cdc333ae',
        },
    ]

    for test in tests:
        check(test['msg'], test['bitlen'], test['digest'])

    assert (
        Sha256bit(b'\x00', bitlen=1).hexdigest() == 'bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375'
    )


def check_against_nist_cavp():
    print("check against 'short' and 'long' bit oriented test vectors from NIST CAVP")
    # (https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabittestvectors.zip)

    from pathlib import Path

    resource_path = Path(__file__).parent
    for tv_file in ['SHA256ShortMsg.rsp', 'SHA256LongMsg.rsp']:
        tv_path = resource_path.joinpath(tv_file)
        with open(tv_path) as f:
            for line in f:
                if line.startswith('Len'):
                    bitlen = int(re.search(r'Len = (.+)', line).group(1))
                if line.startswith('Msg'):
                    msg = Utils.ba(re.search(r'Msg = (.+)', line).group(1))
                    if bitlen == 0:
                        msg = bytes(0)
                if line.startswith('MD'):
                    md = re.search(r'MD = (.+)', line).group(1)
                    check(msg, bitlen, md)


def check_api():
    print('check API')
    msg = msg_generator(bytes(0), 300 * 8)
    expected = hashlib.sha256(msg).digest()
    # print(Utils.hexstr(msg))
    # print(Utils.hexstr(expected))
    assert expected == Sha256bit(msg).digest()
    for len1 in range(0, len(msg) * 8):
        dut1 = Sha256bit()
        dut1.update(msg[:len1])
        state = dut1.export_state()
        dut2 = Sha256bit.import_state(state)
        dut2.update(msg[len1:])
        assert expected == dut2.digest()
    for len1 in range(1, len(msg) * 8):
        dut = Sha256bit()
        remaining = len(msg)
        p = 0
        while remaining > 0:
            chunk = msg[p : p + len1]
            dut.update(chunk, bitlen=len(chunk) * 8)
            p += len1
            remaining -= len1
        assert expected == dut.digest()
        state = dut.export_state()
        dut2 = Sha256bit.import_state(state)
        assert expected == dut2.digest()
    dut = Sha256bit(b'\x00', bitlen=1)
    state = dut.export_state()
    dut2 = Sha256bit.import_state(state)
    assert dut2.hexdigest() == 'bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375'


if __name__ == '__main__':
    check_api()
    check_hardcoded_test_vectors()
    check_against_nist_cavp()
    check_against_hashlib(n_seeds=3, max_length=1024 * 4)
    print('All test PASS')
