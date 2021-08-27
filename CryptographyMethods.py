"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""


class CryptographyMethods:
    class Hashing:
        supported_hash_methods = [
            "argon2id",
            "pbkdf2:sha256"
        ]

        @staticmethod
        def generate_password_hash(password, method: str = "argon2id", prov_salt=None):
            if method == "argon2id":
                from argon2 import PasswordHasher
                crypt_er = PasswordHasher()
                return crypt_er.hash(str(password))

            elif method == "pbkdf2:sha256":
                from secrets import choice
                from hashlib import pbkdf2_hmac
                salt_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                if not prov_salt:
                    salt = "".join(choice(salt_chars) for _ in range(16))
                    salt = salt.encode("utf-8")
                    byte_password = str(password).encode("utf-8")
                    args = method[7:].split(":").pop(0)
                    h = pbkdf2_hmac(args, byte_password, salt, 260000).hex()
                    actual_method = f"$pbkdf2:{args}:{260000}"
                    return f"{actual_method}${salt}${h}"
                else:
                    salt = prov_salt[2:-1].encode("utf-8")
                    byte_password = password.encode("utf-8")
                    args = method[7:].split(":").pop(0)
                    h = pbkdf2_hmac(args, byte_password, salt, 260000).hex()
                    actual_method = f"$pbkdf2:{args}:{260000}"
                    return f"{actual_method}${salt}${h}"

            else:
                return f"We don't support '{method}' method yet. \n" \
                       f"Here are the supported methods : {CryptographyMethods.Hashing.supported_hash_methods}"

        @staticmethod
        def check_password_hash(secret, password):
            if "$argon" in secret:
                from argon2 import PasswordHasher, exceptions
                crypt_er = PasswordHasher()
                try:
                    return crypt_er.verify(secret, str(password))
                except exceptions.VerifyMismatchError:
                    return False
            elif "$pbkdf2" in secret:
                method, prov_salt, hashval = secret[1:].split("$", 2)
                import hmac
                return hmac.compare_digest(
                    CryptographyMethods.Hashing.generate_password_hash(
                        password, method="pbkdf2:sha256", prov_salt=prov_salt)[1:].split("$", 2)[2],
                    hashval
                )
            else:
                raise TypeError("Unsupported Hash-Type\nTry using the following\n"
                                f"{CryptographyMethods.Hashing.supported_hash_methods}")
