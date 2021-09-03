"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""
from AuthAlpha import AuthAlpha

if __name__ == '__main__':

    pbkdf2 = AuthAlpha.Hashing("pbkdf2:sha256")
    # You can change the argument to sha1, sha224, sha384, sha512

    """
    generate_hash_password(self, password: Any, prov_salt: Any = None) -> str
    Method will generate a pbkdf2 hash
    Parameters are kept default, salt will be generated randomly.
    You can also provide your own salt but only with pbkdf2 and scrypt algorithms, but that is not recommended.
    """

    hashed = pbkdf2.generate_password_hash("SuP#rS€cR€TPass")
    print(hashed)

    print("When pass is correct -> ", pbkdf2.check_password_hash(hashed, "SuP#rS€cR€TPass"))  # Will return True
    print("When pass is not correct -> ", pbkdf2.check_password_hash(hashed, "NotMyPassword"))  # Will return False

    # If you input a non string to generate_password_hash or check_password_hash,
    # it will automatically type-cast it to string

    hashed = pbkdf2.generate_password_hash(1234567890)
    print(hashed)
    print("When pass is correct -> ", pbkdf2.check_password_hash(hashed, 1234567890))  # Will return True

    # When you provide your own salt:

    hashed = pbkdf2.generate_password_hash("Secret", prov_salt="mayankvats".encode("utf-8"))
    print(hashed)
    print("When pass is correct -> ", pbkdf2.check_password_hash(hashed, "Secret"))
