"""
Copyright (C) 2021 Mayank Vats
See license.txt

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License v3
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import importlib


class AuthAlpha:
    class PassHashing:

        def __init__(self, algorithm):
            self.algorithm = algorithm
            self.supported_hash_methods = [
                "argon2id",
                "pbkdf2:sha1",
                "pbkdf2:sha224",
                "pbkdf2:sha256",
                "pbkdf2:sha384",
                "pbkdf2:sha512",
                "bcrypt",
                "scrypt"
            ]

        def generate_password_hash(self, password, cost: int = None, prov_salt: bytes = None):
            """
            This method generates a hash pertaining to a specified algorithm,
            see supported_hash_algorithms.
            :param cost: Specify number of iterations for a certain algorithm,
            default values are chosen sensibly but you can still change them.
            (NOT APPLICABLE FOR ARGON2ID(TBD))
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
                DEFAULT_ITERATIONS = 300000
                if not prov_salt:
                    # Generating a random salt and encoding it to bytes
                    salt = "".join(choice(salt_chars) for _ in range(16)).encode("utf-8")
                    # Type-casting the inputted password to string and then encoding it to bytes.
                    byte_password = str(password).encode("utf-8")
                    args = self.algorithm[7:].split(":").pop(0)
                    # self.algorithm[7:].split(":") returns a list with only one element, pop(0) returns that element
                    # The above args object will contain the info on whether algorithm is SHA256 or SHA512
                    if not cost:
                        h = pbkdf2_hmac(args, byte_password, salt, DEFAULT_ITERATIONS).hex()  # Default rounds of pbkdf2
                        actual_method = f"$pbkdf2:{args}:{DEFAULT_ITERATIONS}"
                        return f"{actual_method}${salt}${h}"
                    else:
                        h = pbkdf2_hmac(args, byte_password, salt, cost).hex()  # specified number of rounds
                        actual_method = f"$pbkdf2:{args}:{cost}"
                        return f"{actual_method}${salt}${h}"
                else:
                    salt = prov_salt  # In-case the user provides a salt, hashing is done using it. type(salt) is bytes
                    byte_password = str(password).encode("utf-8")
                    args = self.algorithm[7:].split(":").pop(0)
                    if not cost:
                        h = pbkdf2_hmac(args, byte_password, salt, DEFAULT_ITERATIONS).hex()
                        actual_method = f"$pbkdf2:{args}:{DEFAULT_ITERATIONS}"
                        return f"{actual_method}${salt}${h}"
                    else:
                        h = pbkdf2_hmac(args, byte_password, salt, cost).hex()  # specified number of rounds
                        actual_method = f"$pbkdf2:{args}:{cost}"
                        return f"{actual_method}${salt}${h}"

            elif self.algorithm == "bcrypt":
                from bcrypt import hashpw, gensalt
                if not cost:
                    return f"$bcrypt${hashpw(str(password).encode('utf-8'), gensalt(13))}"
                else:
                    return f"$bcrypt${hashpw(str(password).encode('utf-8'), gensalt(cost))}"

            elif self.algorithm == "scrypt":
                from scrypt import hash
                from secrets import choice
                salt_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                DEFAULT_ITERATIONS = 14  # 2^14
                if not prov_salt:
                    # Generating a random salt and encoding it to bytes
                    salt = "".join(choice(salt_chars) for _ in range(16)).encode("utf-8")
                    # Type-casting the inputted password to string and then encoding it to bytes.
                    byte_password = str(password).encode("utf-8")
                    if not cost:
                        hashed = hash(byte_password, salt).hex()
                        return f"$scrypt$N={DEFAULT_ITERATIONS}$r=8$p=1${salt}${hashed}"
                    else:
                        hashed = hash(byte_password, salt, N=1 << cost).hex()
                        return f"$scrypt$N={cost}$r=8$p=1${salt}${hashed}"

                else:
                    salt = prov_salt  # In-case the user provides a salt, hashing is done using it. type(salt) is bytes
                    byte_password = str(password).encode("utf-8")
                    if not cost:
                        hashed = hash(byte_password, salt).hex()
                        return f"$scrypt$N={DEFAULT_ITERATIONS}$r=8$p=1${salt}${hashed}"
                    else:
                        hashed = hash(byte_password, salt, N=1 << cost).hex()
                        return f"$scrypt$N={cost}$r=8$p=1${salt}${hashed}"

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
                    self.generate_password_hash(password,
                                                cost=int(method[14:]),
                                                prov_salt=prov_salt.encode("utf-8"))[1:].split("$", 2)[2],
                    hashval
                )

            elif "$bcrypt" in secret:
                from bcrypt import hashpw
                salt = f"$2b${secret[14:16]}${secret[17:39]}".encode("utf-8")
                hashed = f'$bcrypt${hashpw(str(password).encode("utf-8"), salt)}'
                return secret == hashed

            elif "$scrypt" in secret:
                from scrypt import hash
                secret_data = secret[1:].split("$", 5)
                hashed, prov_salt = secret_data[5], secret_data[4][2:-1]
                return hashed == self.generate_password_hash(password,
                                                             cost=int(secret_data[1][2:]),
                                                             prov_salt=prov_salt)[1:].split("$", 5)[5]

            else:
                raise TypeError("Unsupported Hash-Type\nTry using the following\n"
                                f"{self.supported_hash_methods}")

    class NonPassHashing:

        def __init__(self, algorithm):
            self.algorithm = algorithm
            self.supported_hash_methods = [
                "sha1",
                "sha224",
                "sha256",
                "sha384",
                "sha512",
                "sha3_224",
                "sha3_256",
                "sha3_384",
                "sha3_512"
            ]

        def generate_file_hash(self, file):
            if self.algorithm in self.supported_hash_methods:
                import importlib
                package = importlib.__import__("hashlib", fromlist=self.supported_hash_methods)
                h = getattr(package, self.algorithm)()
                f = open(file, "rb")

                # loop till the end of the file
                chunk = 0
                while chunk != b'':
                    # read only 1024 bytes at a time
                    chunk = f.read(1024)
                    h.update(chunk)

                return h.hexdigest()

            else:
                return f"We don't support '{self.algorithm}' method yet. \n" \
                       f"Here are the supported methods : {self.supported_hash_methods}"

        def check_file_hash(self, file, digest):
            if self.algorithm in self.supported_hash_methods:
                return self.generate_file_hash(file) == digest


if __name__ == '__main__':

    hashes_to_hashes = AuthAlpha.PassHashing("argon2id")
    # This section illustrates common errors and their work-around
    # If you provide a hash digest which is not recognized Type error will be raised
    # check_hash("NOTRECOGNIZED", 1234567890)

    """
    Traceback (most recent call last):
        raise TypeError("Unsupported Hash-Type\nTry using the following\n"
    TypeError: Unsupported Hash-Type
    Try using the following
    ['argon2id', 'pbkdf2:sha1', 'pbkdf2:sha224', 'pbkdf2:sha256', 'pbkdf2:sha384', 'pbkdf2:sha512', 'bcrypt', 'scrypt']
    """

    # You can catch the above exception like so:

    try:
        hashes_to_hashes.check_password_hash("NOTRECOGNIZED", 1234567890)
    except TypeError as e:
        print(e, "\n")

    # You can print Supported list on demand like so:

    print("Supported Hash Methods: \n", hashes_to_hashes.supported_hash_methods)
