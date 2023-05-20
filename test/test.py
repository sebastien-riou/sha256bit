if __name__ == '__main__':
    import hashlib
    from pysatl import Utils
    import re
    from sha256bit import sha256bit

    print("check against hashlib")

    assert hashlib.sha256("abc".encode()).digest() == sha256bit("abc".encode()).digest()

    def checkAgainstHashLib(seed,msgBitLen):
        lastBlockBitLen = msgBitLen % 512
        l2block = hashlib.sha256(seed).digest()
        l2block += hashlib.sha256(l2block).digest()
        blockBitLen = len(l2block)*8
        assert blockBitLen == 64*8
        expected = hashlib.sha256()
        dut = sha256bit()
        bitlen=0
        while(bitlen+blockBitLen<msgBitLen):
            expected.update(l2block)
            dut.update(l2block)
            bitlen += blockBitLen
            l2block = hashlib.sha256(l2block).digest()
            l2block += hashlib.sha256(l2block).digest()
        # last block
        l2block = l2block[0:lastBlockBitLen//8]
        assert len(l2block) == lastBlockBitLen //8
        expected.update(l2block)
        dut.update(l2block)
        assert expected.digest() == dut.digest()

    for seedByte in range(0, 5):
        for msgBitLen in range(0,1024*4, 8):
            seed = bytearray([seedByte])
            checkAgainstHashLib(seed,msgBitLen)

    print("check few minimal hardcoded test vectors")
    def check(msg, bitlen, sig):
        m = sha256bit()
        if isinstance(msg,str):
            msg=msg.encode('ascii')
        descr = "msg      = "+Utils.hexstr(msg)+"\n"
        descr+= "bitlen   = %d\n"%bitlen
        descr+= "expected = "+sig+"\n"
        try:
            
            m.update(msg, bitlen=bitlen)
            digest = m.hexdigest()
        except Exception as e:
            print(descr)
            raise e
        errMsg ='\n'
        errMsg+= descr
        errMsg+= "digest   = "+digest+"\n"
        assert digest == sig, errMsg

    tests = [
        {"msg":"","bitlen":0,"digest":'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
        {"msg":"a","bitlen":8,"digest":'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb'},
        {"msg":Utils.ba("00"),"bitlen":1,"digest":'bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375'},
        {"msg":Utils.ba("80"),"bitlen":2,"digest":'18f331f626210ff9bad6995d8cff6e891adba50eb2fdbddcaa921221cdc333ae'},
    ]

    for test in tests:
        check(test["msg"],test["bitlen"],test["digest"])

    assert sha256bit(b'\x00',bitlen=1).hexdigest() == 'bd4f9e98beb68c6ead3243b1b4c7fed75fa4feaab1f84795cbd8a98676a2a375'


    print("check against 'short' and 'long' bit oriented test vectors from NIST CAVP")
    # (https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabittestvectors.zip)

    from pathlib import Path
    resource_path = Path(__file__).parent 
    for tvFile in ["SHA256ShortMsg.rsp","SHA256LongMsg.rsp"]:
        tvPath = resource_path.joinpath(tvFile)
        with open(tvPath) as f:
            for l in f:
                if l.startswith("Len"):
                    bitlen = int(re.search(r"Len = (.+)",l).group(1))
                if l.startswith("Msg"):
                    msg = Utils.ba(re.search(r"Msg = (.+)",l).group(1))
                    if bitlen==0:
                        msg=bytes(0)
                if l.startswith("MD"):
                    MD = re.search(r"MD = (.+)",l).group(1)
                    check(msg,bitlen,MD)

    print("All test PASS")
                
            
    