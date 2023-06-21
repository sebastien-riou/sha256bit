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
        {
            'msg': Utils.ba(
                'E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6'
                + 'E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4'
            ),
            'bitlen': 447,
            'digest': 'c123373c1f86be0ce17b4786eb7ef6efe5c343ee43be0ab5be2fa3d8b56d94c6',
        },
        {
            'msg': Utils.ba(
                'E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6'
                + 'E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4'
            ),
            'bitlen': 448,
            'digest': 'd32a8ff92fbff08265fa8afc6d932a48a0548d7eb79a27c039d361304472df52',
        },
        {
            'msg': Utils.ba(
                'E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6'
                + 'E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 00'
            ),
            'bitlen': 449,
            'digest': 'd92d5c37640bd3f5c692a09394cd6969485815b4c42da7367850def5d517ef6f',
        },
        {
            'msg': Utils.ba(
                'E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6'
                + 'E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56'
            ),
            'bitlen': 511,
            'digest': '618eaf0976a52617868d69aacc7ccefe0237319fa2e7b08511bd11bd0a5fdcae',
        },
        {
            'msg': Utils.ba(
                'E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6'
                + 'E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56'
            ),
            'bitlen': 512,
            'digest': '5fe4463c6c44975ee6ecc2929fc266c5919a867c9c4993216f20a65f992a1a00',
        },
        {
            'msg': Utils.ba(
                'E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6'
                + 'E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56 00'
            ),
            'bitlen': 513,
            'digest': '7db0e54c522ae26960ae971a33744cd78cf0df06f965ab4458f1fddf61510168',
        },
        {
            'msg': Utils.ba(
                'E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6'
                + 'E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56 5F E4 46'
                + '3C'
            ),
            'bitlen': 512 + 32,
            'digest': 'cc87d0d00ee74d5b2f47177770ff784f5a72b18933146533fbc1bcac6c7007b9',
        },
        {
            'msg': Utils.ba(
                'E3 B0 C4 42 98 FC 1C 14 9A FB F4 C8 99 6F B9 24 27 AE 41 E4 64 9B 93 4C A4 95 99 1B 78 52 B8 55 5D F6'
                + 'E0 E2 76 13 59 D3 0A 82 75 05 8E 29 9F CC 03 81 53 45 45 F5 5C F4 3E 41 98 3F 5D 4C 94 56 5F E4 46'
                + '3C 6C 44 97 5E E6 EC C2 92 9F C2 66 C5 91 9A 86 7C 9C 49 93 21 6F 20 A6 5F 99 2A 1A 00 3B 6C D9 97'
                + '66 FA 87 0F DC A0 7E 1A 8E 38 D5 F4 DA 51 C7 15 1F 8D 47 EE'
            ),
            'bitlen': 512 + 447,
            'digest': '99864bc34a68094ff6beb97fb66db2b9e869e1e5611b2ad2c539b009011fdbc6',
        },
        {
            'msg': msg_generator(bytes(0), 3),
            'bitlen': 3,
            'digest': '8287ea50445e9ddd80b791cf413e74d152a577b8441b93fa29d88edc830f4400',
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
