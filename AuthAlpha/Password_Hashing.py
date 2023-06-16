"""
Copyright (C) 2021-2022 Mayank Vats
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
__version__ = "0.8.3alpha"

"""


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

    def __repr__(self):
        return "PassHashing('{}')".format(self.algorithm)

    def __str__(self):
        return f"\033[1mPassword Hashing Class [PassHashing]\033[0m. \033[92mAlgorithm:\033[0m \033[1m{self.algorithm}\033[0m "

    def generate_password_hash(self, password: str, cost: int = None, prov_salt: bytes = None):
        """
        :param cost: Specify number of iterations for a certain algorithm,
        default values are chosen sensibly, but you can still change them.
        (NOT APPLICABLE FOR ARGON2ID(TBD))
        :param password: type(password) is str
        :param prov_salt: (optional) provide a bytes-like salt for hashing
        only applicable for pbkdf2 hashes.
        :return: str(hash)
        This method generates a hash pertaining to a specified algorithm,
        see supported_hash_algorithms.
        """

        if self.algorithm == "argon2id":
            from argon2 import PasswordHasher
            crypt_er = PasswordHasher()
            return crypt_er.hash(password)

        elif self.algorithm.startswith("pbkdf2:"):
            from secrets import choice
            from hashlib import pbkdf2_hmac
            SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            DEFAULT_ITERATIONS = 300000

            if not prov_salt:
                # Generating a random salt and encoding it to bytes
                salt = "".join(choice(SALT_CHARS) for _ in range(16)).encode("utf-8")
                # Type-casting the inputted password to string and then encoding it to bytes.
                byte_password = password.encode("utf-8")
                args = self.algorithm.split(":")[1]

                # Default rounds of pbkdf2
                if not cost:
                    h = pbkdf2_hmac(args, byte_password, salt, DEFAULT_ITERATIONS).hex()
                    actual_method = f"$pbkdf2:{args}:{DEFAULT_ITERATIONS}"
                    return f"{actual_method}${salt.decode('utf-8')}${h}"

                # Custom rounds of pbkdf2
                else:
                    h = pbkdf2_hmac(args, byte_password, salt, cost).hex()  # specified number of rounds
                    actual_method = f"$pbkdf2:{args}:{cost}"
                    return f"{actual_method}${salt.decode('utf-8')}${h}"

            else:
                # In-case the user provides a salt, hashing is done using it. type(salt) is bytes
                byte_password = password.encode("utf-8")
                args = self.algorithm.split(":")[1]

                if not cost:
                    h = pbkdf2_hmac(args, byte_password, prov_salt, DEFAULT_ITERATIONS).hex()
                    actual_method = f"$pbkdf2:{args}:{DEFAULT_ITERATIONS}"
                    return f"{actual_method}${prov_salt.decode('utf-8')}${h}"
                else:
                    h = pbkdf2_hmac(args, byte_password, prov_salt, cost).hex()  # specified number of rounds
                    actual_method = f"$pbkdf2:{args}:{cost}"
                    return f"{actual_method}${prov_salt.decode('utf-8')}${h}"

        elif self.algorithm == "bcrypt":
            from bcrypt import hashpw, gensalt
            DEFAULT_ITERATIONS = 13  # 2^13

            if not prov_salt:
                if not cost:
                    return f"$bcrypt{hashpw(password.encode('utf-8'), gensalt(DEFAULT_ITERATIONS)).decode('utf-8')}"
                else:
                    return f"$bcrypt{hashpw(password.encode('utf-8'), gensalt(cost)).decode('utf-8')}"
            elif prov_salt:
                if prov_salt.endswith(b".") or prov_salt.endswith(b"O") or prov_salt.endswith(b"e") or prov_salt.endswith(b"u"):
                    return f"$bcrypt{hashpw(password.encode('utf-8'), prov_salt).decode('utf-8')}"
                else:
                    raise(TypeError("Invalid Salt\n(AuthAlpha): The salt must end with '.', 'O', "
                                    "'e' or 'u' in bcrypt. See .."))

        elif self.algorithm == "scrypt":
            from scrypt import hash
            from secrets import choice
            SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            DEFAULT_ITERATIONS = 14  # 2^14
            if not prov_salt:
                # Generating a random salt and encoding it to bytes
                salt = "".join(choice(SALT_CHARS) for _ in range(16)).encode("utf-8")
                byte_password = password.encode("utf-8")

                if not cost:
                    hashed = hash(byte_password, salt).hex()
                    return f"$scrypt$N={DEFAULT_ITERATIONS}$r=8$p=1${salt.decode('utf-8')}${hashed}"
                else:
                    hashed = hash(byte_password, salt, N=1 << cost).hex()
                    return f"$scrypt$N={cost}$r=8$p=1${salt.decode('utf-8')}${hashed}"

            else:
                byte_password = password.encode("utf-8")
                if not cost:
                    hashed = hash(byte_password, prov_salt).hex()
                    return f"$scrypt$N={DEFAULT_ITERATIONS}$r=8$p=1${prov_salt.decode('utf-8')}${hashed}"
                else:
                    hashed = hash(byte_password, prov_salt, N=1 << cost).hex()
                    return f"$scrypt$N={cost}$r=8$p=1${prov_salt.decode('utf-8')}${hashed}"

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
                self.generate_password_hash(password,
                                            cost=int(method.split(":")[2]),
                                            prov_salt=prov_salt.encode("utf-8"))[1:].split("$", 2)[2],
                hashval
            )

        elif "$bcrypt" in secret:
            from bcrypt import hashpw
            hash_data = secret[1:].split("$")
            salt = f"${hash_data[1]}${hash_data[2]}${hash_data[3][:22]}".encode("utf-8")
            hashed = self.generate_password_hash(password, prov_salt=salt)
            return secret == hashed

        elif "$scrypt" in secret:
            from scrypt import hash
            secret_data = secret[1:].split("$")
            hashed, prov_salt = secret_data[5], secret_data[4].encode('utf-8')
            return hashed == self.generate_password_hash(password,
                                                         cost=int(secret_data[1][2:]),
                                                         prov_salt=prov_salt)[1:].split("$")[5]

        else:
            raise TypeError("Unsupported Hash-Type\nTry using the following\n"
                            f"{self.supported_hash_methods}")


if __name__ == '__main__':

    hashes_to_hashes = PassHashing("argon2id")
    # This section illustrates common errors and their work-around
    # If you provide a hash digest which is not recognized Type error will be raised
    # check_hash("NOTRECOGNIZED", 1234567890)
    print(hashes_to_hashes)

    """
    Traceback (most recent call last):
        raise TypeError("Unsupported Hash-Type\nTry using the following\n"
    TypeError: Unsupported Hash-Type
    Try using the following
    ['argon2id', 'pbkdf2:sha1', 'pbkdf2:sha224', 'pbkdf2:sha256', 'pbkdf2:sha384', 'pbkdf2:sha512', 'bcrypt', 'scrypt']
    """

    # You can catch the above exception like so:

    try:
        hashes_to_hashes.check_password_hash("NOTRECOGNIZED", str(1234567890))
    except TypeError as e:
        print(e, "\n")

    # You can print Supported list on demand like so:

    print("Supported Hash Methods: \n", hashes_to_hashes.supported_hash_methods)

    # See <https://github.com/Theorist-Git/AuthAlpha> for tutorials.
