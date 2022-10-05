# coding=utf-8
from hashlib import md5

from ldap_sync.utils import DEFAULT_ENCODING


def hash_md5(value, prefix='', encoding=None):
    """Function that can be used to encrypt the username
    :param encoding:  value encoding
    :param value: str
    :param prefix: The prefix helps maintain a unique username
    :return: str
    """
    if encoding is None:
        encoding = DEFAULT_ENCODING
    return md5(bytes(prefix + value, encoding)).hexdigest()
