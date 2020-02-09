#!/usr/bin/env python3


from abc import ABCMeta, abstractproperty, abstractmethod
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as sz
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import utils
import base64
import binascii


class Key(object, metaclass=ABCMeta):
    def __init__(self):
        pass

    @abstractproperty
    def __str__(self):
        pass

    @abstractproperty
    def __len__(self):
        return len(str(self))

    @abstractproperty
    def base64(self):
        pass

    @property
    def file(self):
        return getattr(self, '_file', None)

    @file.setter
    def file(self, location):
        setattr(self, '_file', location)

    @abstractmethod
    def write_file(self, location):
        contents = str(self)
        self.file = location
        with open(self.file, "w") as key_file:
            key_file.write(contents)


class PEMPrivateKey(Key):
    def __init__(self, private_key=None):
        '''
        takes in a b64 encoded string or standard text private key and returns a PrivateKey object
        '''
        if private_key:
            base64_data = False
            if isinstance(private_key, str):
                private_key = private_key.encode()
            try:
                data = base64.b64encode(base64.b64decode(private_key))
                if data == private_key:
                    private_key = base64.b64decode(data)
                    base64_data = True
            except binascii.Error:
                pass
            if isinstance(private_key, bytes) and not base64_data:
                self.key = sz.load_pem_private_key(
                    private_key, None, default_backend())
            elif isinstance(private_key, bytes) and base64_data:
                data = utils.int_from_bytes(private_key, 'big')
                self.key = ec.derive_private_key(data, ec.SECP256R1(), default_backend())
        else:
            self.key = ec.generate_private_key(
                ec.SECP256R1(), default_backend())
        self._pub_key = PEMPublicKey(self.key.public_key())

    def __str__(self):
        return self.key.private_bytes(encoding=sz.Encoding.PEM, format=sz.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=sz.NoEncryption()).decode()

    def __bytes__(self):
        return utils.int_to_bytes(self.key.private_numbers().private_value)

    def __len__(self):
        return len(str(self))

    def __eq__(self, other):
        if self.base64 != other.base64:
            return False
        if bytes(self) != bytes(other):
            return False
        if len(self) != len(other):
            return False
        if str(self) != str(other):
            return False
        return True

    @property
    def pub_key(self):
        return self._pub_key

    @property
    def base64(self):
        return base64.b64encode(bytes(self)).decode()

    def write_file(self, location='/tmp/dev-key.pem'):
        super(PEMPrivateKey, self).write_file(location)

    def prepare_keys(self):
        self.pub_key.write_file()
        self.write_file()


class PEMPublicKey(Key):
    def __init__(self, pub_key=None):
        if isinstance(pub_key, ec.EllipticCurvePublicKey):
            self.key = pub_key
        else:
            if isinstance(pub_key, str):
                pub_key = pub_key.encode()
            try:
                data = base64.b64encode(base64.b64decode(pub_key))
                if data == pub_key:
                    pub_num = ec.EllipticCurvePublicKey.from_encoded_point(curve=ec.SECP256R1(), data=base64.b64decode(pub_key))
                    self.key = pub_num
            except ValueError:
                print("not base64 encoded point")
            if isinstance(pub_key, bytes) and not hasattr(self, 'key'):
                if '-----BEGIN PUBLIC KEY-----' not in pub_key.decode():
                    pub_key = self.repair_key(pub_key)
                self.key = sz.load_pem_public_key(pub_key, default_backend())

    def __str__(self):
        return self.key.public_bytes(sz.Encoding.PEM, sz.PublicFormat.SubjectPublicKeyInfo).decode()

    def __len__(self):
        return len(str(self))

    def __bytes__(self):
        return self.key.public_bytes(sz.Encoding.X962, sz.PublicFormat.UncompressedPoint)

    def __eq__(self, other):
        if self.base64 != other.base64:
            return False
        if bytes(self) != bytes(other):
            return False
        if len(self) != len(other):
            return False
        if str(self) != str(other):
            return False
        return True

    @property
    def base64(self):
        return base64.b64encode(bytes(self)).decode()

    def write_file(self, location='/tmp/dev-pub.pem'):
        super(PEMPublicKey, self).write_file(location)

    @staticmethod
    def repair_key(pub_key):
        begin = '-----BEGIN PUBLIC KEY-----\n'
        end = '\n-----END PUBLIC KEY-----\n'
        fixed = ''.join([begin, pub_key, end])
        return fixed
