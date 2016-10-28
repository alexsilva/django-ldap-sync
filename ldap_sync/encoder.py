from hashlib import md5


def hash_md5(value, prefix=''):
    """Function that can be used to encrypt the username
    :param value: str
    :param prefix: The prefix helps maintain a unique username
    :return: str
    """
    return md5(prefix + value).hexdigest()
