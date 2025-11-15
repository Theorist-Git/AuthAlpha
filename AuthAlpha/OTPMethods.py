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

import base64
from os import urandom
from binascii import Error as Binascii_error

PBKDF2_DKLEN = 32
PBKDF2_ITERS = 310000

class TwoFactorAuth:

    def __repr__(self):
        return "TwoFactorAuth()"

    def __str__(self):
        return "Two Factor Authentication Class[TwoFactorAuth]"

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
    def encrypt(key: bytes, source: bytes) -> str:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256

        salt = urandom(16)
        derived_key = PBKDF2(key.decode("utf-8"), salt, dkLen=PBKDF2_DKLEN, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
        cipher = AES.new(derived_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(source)

        packed_data = b"".join([salt, cipher.nonce, tag, ciphertext])

        return base64.b64encode(packed_data).decode('latin-1')

    @staticmethod
    def decrypt(key: bytes, source: str, decode=True) -> str:
        from Crypto.Cipher import AES
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256

        try:
            data = base64.b64decode(source.encode('latin-1'))
            # Extract all the parts based on their known lengths
            # Salt=16, Nonce=16 (GCM default), Tag=16 (GCM default)
            salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]
            derived_key = PBKDF2(key.decode("utf-8"), salt, dkLen=PBKDF2_DKLEN, count=PBKDF2_ITERS, hmac_hash_module=SHA256)

            cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)

            # Decrypt and VERIFY.
            # .decrypt_and_verify() will automatically check the 'tag'.
            # If the tag is invalid (meaning the data was tampered with
            # or the key is wrong), it will raise a ValueError.
            plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)

            return plaintext_bytes.decode('utf-8')

        except (ValueError, KeyError, Binascii_error):
            raise ValueError("Error Decrypting")
