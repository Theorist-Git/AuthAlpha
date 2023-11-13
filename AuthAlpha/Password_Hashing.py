"""
Copyright (C) 2021-2023 Mayank Vats
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

__author__ = "Mayank Vats"
__email__ = "dev-theorist.e5xna@simplelogin.com"
__Description__ = "AuthAlpha: A package to manage Hashing and OTP generation."
__version__ = "0.8.5alpha"

"""
import os


class PassHashing:

    def __init__(self, algorithm):
        self.algorithm = algorithm
        self.supported_hash_methods = (
            "argon2id",
            "pbkdf2:sha1",
            "pbkdf2:sha224",
            "pbkdf2:sha256",
            "pbkdf2:sha384",
            "pbkdf2:sha512",
            "bcrypt",
            "scrypt"
        )

    def __repr__(self):
        return "PassHashing('{}')".format(self.algorithm)

    def __str__(self):
        return f"\033[1mPassword Hashing Class [PassHashing]\033[0m. \033[92mAlgorithm:\033[0m \033" \
               f"[1m{self.algorithm}\033[0m "

    def generate_password_hash(self, password: str, cost: int = None, salt: bytes = None):
        """
        :param cost: Specify number of iterations for a certain algorithm,
        default values are chosen sensibly, but you can still change them.
        (NOT APPLICABLE FOR ARGON2ID(TBD))
        :param password: type(password) is str
        :param salt: (optional) provide a bytes-like salt for hashing
        only applicable for pbkdf2 hashes.
        :return: str(hash)
        This method generates a hash pertaining to a specified algorithm,
        see supported_hash_algorithms.
        """

        if self.algorithm == "argon2id":
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            return ph.hash(password)

        elif self.algorithm.startswith("pbkdf2:"):
            from secrets import choice
            from hashlib import pbkdf2_hmac
            SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

            if not cost:
                ITERATIONS = 300000  # Default Iterations
            else:
                ITERATIONS = cost

            # Encoding password string to bytes
            byte_password = password.encode("utf-8")

            # self.algorithm = pbkdf2:sha---
            # self.algorithm.split(":")[1] = `sha---`
            sha_variant = self.algorithm.split(":")[1]

            if not salt:
                # Generating a random salt and encoding it to bytes
                salt = "".join(choice(SALT_CHARS) for _ in range(16)).encode("utf-8")

            h = pbkdf2_hmac(sha_variant, byte_password, salt, ITERATIONS).hex()
            hash_prefix = f"$pbkdf2:{sha_variant}:{ITERATIONS}"

            return f"{hash_prefix}${salt.decode('utf-8')}${h}"

        elif self.algorithm == "bcrypt":
            from bcrypt import hashpw, gensalt

            B64_SALT_LEN = 22

            if not cost:
                ITERATIONS = 13  # Default Iterations = 2^13
            else:
                ITERATIONS = cost

            if not salt:
                # Salt generated by bcrypt
                salt = gensalt(ITERATIONS)

            else:
                salt_check = salt.endswith(b".") or salt.endswith(b"O") or salt.endswith(b"e") or salt.endswith(b"u")
                if not salt_check:
                    raise (TypeError("Invalid Salt\n(AuthAlpha): The salt must end with '.', 'O', "
                                     "'e' or 'u' in bcrypt. See https://github.com/Theorist-Git/AuthAlpha/commit"
                                     "/b00b7ce1b33c64d61da85ea2b657617008f16abe"))
                if len(salt) != B64_SALT_LEN:
                    raise TypeError("salt must be 22 base 64 encoded character or 16 bytes long. Eg: \n "
                                    "'XeFRr+UT49ZF0DKDyIPMh.'")
                salt = b"$" + b"2b" + b"$" + ("%2.2u" % ITERATIONS).encode("ascii") + b"$" + salt

            return f"$bcrypt{hashpw(password.encode('utf-8'), salt).decode('utf-8')}"

        elif self.algorithm == "scrypt":
            from scrypt import hash
            from secrets import choice
            SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

            if not cost:
                ITERATIONS = 14  # Default Iterations = 2^14
            else:
                ITERATIONS = cost

            byte_password = password.encode("utf-8")

            if not salt:
                # Generating a random salt and encoding it to bytes
                salt = "".join(choice(SALT_CHARS) for _ in range(16)).encode("utf-8")

            hashed = hash(byte_password, salt, N=1 << ITERATIONS).hex()

            return f"$scrypt$N={ITERATIONS}$r=8$p=1${salt.decode('utf-8')}${hashed}"

        else:
            return f"We don't support '{self.algorithm}' method yet. \n" \
                   f"Here are the supported methods : {self.supported_hash_methods}"

    def check_password_hash(self, secret: str, password: str):
        """
        Checks a plain text password against a provides hash of a supported algorithm
        see supported_hash_types
        :param secret: hash digest of a certain algorithm
        :param password: Plain-text password
        :return: True or False (password is correct or not)
        """
        if "$argon" in secret:
            from argon2 import PasswordHasher, exceptions
            crypt_er = PasswordHasher()
            try:
                return crypt_er.verify(secret, password)
            except exceptions.VerifyMismatchError:
                return False

        elif "$pbkdf2" in secret:
            method, prov_salt, hashval = secret[1:].split("$", 2)
            import hmac
            return hmac.compare_digest(
                self.generate_password_hash(password, cost=int(method.split(":")[2]), salt=prov_salt.encode("utf-8"))[
                1:].split("$", 2)[2],
                hashval
            )

        elif "$bcrypt" in secret:
            from bcrypt import hashpw

            B64_SALT_LEN = 22

            hash_data = secret[1:].split("$")
            cost = int(hash_data[2])
            salt = hash_data[3][:B64_SALT_LEN].encode("utf-8")

            return secret == self.generate_password_hash(password, cost=cost, salt=salt)

        elif "$scrypt" in secret:
            from scrypt import hash
            secret_data = secret[1:].split("$")
            hashed, prov_salt = secret_data[5], secret_data[4].encode('utf-8')
            return hashed == \
                self.generate_password_hash(password, cost=int(secret_data[1][2:]), salt=prov_salt)[1:].split("$")[5]

        else:
            raise TypeError(f"Unsupported Hash-Type: `{secret}` for algorithm `{self.algorithm}`\nTry using the "
                            f"following\n"
                            f"{self.supported_hash_methods}")


if __name__ == '__main__':

    hashes_to_hashes = PassHashing("argon2id")
    # This section illustrates common errors and their work-around
    # If you provide a hash digest which is not recognized Type error will be raised
    # check_hash("NOTRECOGNIZED", 1234567890)
    print(hashes_to_hashes)

    # You can catch the above exception like so:

    try:
        hashes_to_hashes.check_password_hash("NOTRECOGNIZED", str(1234567890))
    except TypeError as e:
        print(e, "\n")

    # You can print Supported list on demand like this:

    print("Supported Hash Methods: \n", hashes_to_hashes.supported_hash_methods)

    # See <https://github.com/Theorist-Git/AuthAlpha> for tutorials.
