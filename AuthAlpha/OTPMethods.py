"""
Copyright (C) 2021-2025 Mayank Vats
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
__version__ = "0.9.0alpha"

"""


class TwoFactorAuth:

    def __repr__(self):
        return "TwoFactorAuth()"

    def __str__(self):
        return "\033[1mTwo Factor Authentication Class[TwoFactorAuth]\033[0m."

    @staticmethod
    def static_otp(otp_len: int = 6) -> str:
        """
        Used to generate Random ONE-TIME-PASSWORDS which are
        utilized in the app for user verification and authentication.
        Gets SystemRandom class instance out of secrets module and
        generates a random integer in range [a, b].
        :param: otp_len=6: length of the otp
        :return: str(random integer in range [10^n, (10^n) - 1])
        """
        # secure random integer numbers
        from secrets import SystemRandom

        secrets_generator = SystemRandom()
        l_range = (10 ** (otp_len - 1))
        h_range = (l_range * 10) - 1
        otp = secrets_generator.randint(l_range, h_range)
        return str(otp)

    @staticmethod
    def totp(user_name, issuer_name: str, secret_len: int = 64) -> tuple:
        from pyotp import random_base32, TOTP
        token = random_base32(secret_len)
        URL = TOTP(token).provisioning_uri(name=user_name, issuer_name=issuer_name)

        return token, URL

    @staticmethod
    def verify(token: str, otp) -> bool:
        from pyotp import TOTP

        return TOTP(token).verify(str(otp))

    @staticmethod
    def encrypt(key: bytes, source: bytes, encode=True) -> str:
        import base64
        from Crypto.Cipher import AES
        from Crypto.Hash import SHA256
        from Crypto import Random
        key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
        IV = Random.new().read(AES.block_size)  # generate IV
        encryptor = AES.new(key, AES.MODE_CBC, IV)
        padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
        source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
        data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
        return base64.b64encode(data).decode("latin-1") if encode else data

    @staticmethod
    def decrypt(key: bytes, source, decode=True) -> str:
        import base64
        from Crypto.Cipher import AES
        from Crypto.Hash import SHA256
        if decode:
            source = base64.b64decode(source.encode("latin-1"))
        key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
        IV = source[:AES.block_size]  # extract the IV from the beginning
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        data = decryptor.decrypt(source[AES.block_size:])  # decrypt
        padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
        if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
            raise ValueError("Invalid padding...")
        return data[:-padding].decode('utf-8')  # remove the padding
