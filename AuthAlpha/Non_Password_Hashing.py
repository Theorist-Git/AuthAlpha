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
__version__ = "0.8.2alpha"

"""


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
