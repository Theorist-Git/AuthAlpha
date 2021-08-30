"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""


class CryptographyMethods:
    class Hashing:

        def __init__(self, algorithm):
            self.algorithm = algorithm
            self.supported_hash_methods = [
                "argon2id",
                "pbkdf2:sha1",
                "pbkdf2:sha224",
                "pbkdf2:sha256",
                "pbkdf2:sha384",
                "pbkdf2:sha512",
            ]

        def generate_password_hash(self, password, prov_salt: bytes = None):
            """
            This method generates a hash pertaining to a specified algorithm,
            see supported_hash_algorithms.
            :param password: type(password) is str
            :param prov_salt: (optional) provide a bytes-like salt for hashing
            only applicable for pbkdf2 hashes.
            :return: str(hash)
            """
            if self.algorithm == "argon2id":
                from argon2 import PasswordHasher
                crypt_er = PasswordHasher()
                return crypt_er.hash(str(password))

            elif "pbkdf2" in self.algorithm:
                from secrets import choice
                from hashlib import pbkdf2_hmac
                salt_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                if not prov_salt:
                    # Generating a random salt and encoding it to bytes
                    salt = "".join(choice(salt_chars) for _ in range(16)).encode("utf-8")
                    # Type-casting the inputted password to string and then encoding it to bytes.
                    byte_password = str(password).encode("utf-8")
                    args = self.algorithm[7:].split(":").pop(0)
                    # self.algorithm[7:].split(":") returns a list with only one element, pop(0) returns that element
                    # The above args object will contain the info on whether algorithm is SHA256 or SHA512
                    h = pbkdf2_hmac(args, byte_password, salt, 260000).hex()  # 260000 rounds of pbkdf2:args
                    actual_method = f"$pbkdf2:{args}:{260000}"
                    return f"{actual_method}${salt}${h}"
                else:
                    salt = prov_salt  # In-case the user provides a salt, hashing is done using it. type(salt) is bytes
                    byte_password = str(password).encode("utf-8")
                    args = self.algorithm[7:].split(":").pop(0)
                    h = pbkdf2_hmac(args, byte_password, salt, 260000).hex()
                    actual_method = f"$pbkdf2:{args}:{260000}"
                    return f"{actual_method}${salt}${h}"

            else:
                return f"We don't support '{self.algorithm}' method yet. \n" \
                       f"Here are the supported methods : {self.supported_hash_methods}"

        def check_password_hash(self, secret, password):
            """
            Checks a plain text password against a provides hash of a supported algorithm
            see supported_hash_types.
            :param secret: hash digest of a certain algorithm
            :param password: Plain-text password
            :return: True or False (password is correct or not)
            """
            if "$argon" in secret:
                from argon2 import PasswordHasher, exceptions
                crypt_er = PasswordHasher()
                try:
                    return crypt_er.verify(secret, str(password))
                except exceptions.VerifyMismatchError:
                    return False
            elif "$pbkdf2" in secret:
                method, prov_salt, hashval = secret[1:].split("$", 2)
                """
                returns a list like this:
                ['pbkdf2:sha256:260000', "b'eiV3F72mPyVrttd8'", 'hash']
                
                Now the problem is that it returns our originally bytes-type object as a string like so:
                "b'eiV3F72mPyVrttd8'" which when encoded to bytes, returns a bytes-like object with the 
                'b' and the apostrophes. This results in hashes not matching because the new salt is now
                b'"b'eiV3F72mPyVrttd8'"'.
                
                A work-around for that is to slice the string as shown below in the object 'prov_salt'
                """
                prov_salt = prov_salt[2:-1]
                import hmac
                return hmac.compare_digest(
                    self.generate_password_hash(password, prov_salt=prov_salt.encode("utf-8"))[1:].split("$", 2)[2],
                    hashval
                )
            else:
                raise TypeError("Unsupported Hash-Type\nTry using the following\n"
                                f"{self.supported_hash_methods}")


if __name__ == '__main__':

    hashes_to_hashes = CryptographyMethods.Hashing("argon2id")
    # This section illustrates common errors and their work-around
    # If you provide a hash digest which is not recognized Type error will be raised
    # check_hash("NOTRECOGNIZED", 1234567890)

    """
    Traceback (most recent call last):
        raise TypeError("Unsupported Hash-Type\nTry using the following\n"
    TypeError: Unsupported Hash-Type
    Try using the following
    ['pbkdf22id', 'pbkdf2:sha256']
    """

    # You can catch the above exception like so:

    try:
        hashes_to_hashes.check_password_hash("NOTRECOGNIZED", 1234567890)
    except TypeError as e:
        print(e, "\n")

    # You can print Supported list on demand like so:

    print("Supported Hash Methods: \n",  hashes_to_hashes.supported_hash_methods)

