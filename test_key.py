#!/usr/bin/env python3

from Key import PEMPublicKey, PEMPrivateKey





def test_key_types():
    base64a = 'n1v1W9z8F250ou9KwX5G5gkDdT82LDUiEdKNVGGv1W4='
    a = PEMPrivateKey(base64a)
    b = PEMPrivateKey(str(a))
    c = PEMPublicKey(b.pub_key.base64)
    d = PEMPublicKey(str(b.pub_key))
    f = PEMPrivateKey()
    if a == b:
        print(f'Private Data is equivlent')
    if c == d:
        print(f'Public Key data is equivlent')
    if a == f:
        print(f'This is a failure')
        raise ValueError

if __name__ == "__main__":
    test_key_types()
