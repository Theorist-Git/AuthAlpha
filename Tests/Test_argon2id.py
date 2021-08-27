"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""
from CryptographyMethods import CryptographyMethods

argon = CryptographyMethods.Hashing


def generate_hash(password):
    """
    Hashing method defaults to 'argon2id'.
    Parameters are kept default, salt will be generated randomly.
    You can also provide your own salt, but that is not recommended.
    :param password: Plain-text password for which hash is to be generated
    :return: Secure argon2 hash and list of supported hash algorithms
    """
    return argon.generate_password_hash(password)


def check_hash(secret, password):
    """
    Checks the hash of a plain-text password against a hash digest.
    :param secret: Hash digest
    :param password: Plain-text password
    :return: Boolean : True if the secret === password
    """
    return argon.check_password_hash(secret, password)


hashed = generate_hash("SuP#rS€cR€TPass")  # Will generate a argon2 hash
print(hashed)
print(check_hash(hashed, "SuP#rS€cR€TPass"))  # Will return True
print(check_hash(hashed, "NotMyPassword"))    # Will return False

# If you input a non string to generate_password_hash or check_password_hash,
# it will automatically type-cast it to string

hashed = generate_hash(1234567890)
print(hashed)
print(check_hash(hashed, 1234567890))  # Will return True

# If you provide a hash digest which is not recognized Type error will be raised

# check_hash("NOTRECOGNIZED", 1234567890)

"""
Traceback (most recent call last):
    raise TypeError("Unsupported Hash-Type\nTry using the following\n"
TypeError: Unsupported Hash-Type
Try using the following
['argon2id', 'pbkdf2:sha256']
"""

# You can catch the above exception like so:

try:
    check_hash("NOTRECOGNIZED", 1234567890)
except TypeError as e:
    print(e, "\n")

# You can print Supported list on demand like so:

print("Supported Hash Methods: \n", argon.supported_hash_methods)
