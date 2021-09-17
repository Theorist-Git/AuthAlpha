"""
Copyright (C) 2021 Mayank Vats
See license.txt
"""

from AuthAlpha import NonPassHashing

hash_list = NonPassHashing("algo").supported_hash_methods
f1 = "C:\\Users\\mayan\\Desktop\\languages\\Python 3.9\\Projects\\Cryptography\\Algorithm_Implementations\\license.txt"
f2 = "C:\\Users\\mayan\\Desktop\\languages\\Python 3.9\\Projects\\Cryptography\\Algorithm_Implementations\\README.md"
f3 = "C:\\Users\\mayan\\Desktop\\languages\\Python 3.9\\Projects\\Cryptography\\Algorithm_Implementations\\AuthAlpha.py"

print("----------------------------------------------Hashes for f1----------------------------------------------")
for i in hash_list:
    hashed = NonPassHashing(i)
    h = hashed.generate_file_hash(f1)
    print(i, ":", h)


print("----------------------------------------------Hashes for f2----------------------------------------------")
for j in hash_list:

    hashed = NonPassHashing(j)
    h = hashed.generate_file_hash(f2)
    print(j, ":", h)

# SHA256 hash of f1: 81cbae84a29ce7e770bf2bc7b178e50bda0ce8de6067aba661b0bc7b05b562f8
# SHA256 hash of f2: 2c7498404231e3f980b42756c06de5f58cfde6e3e211a059f2e593380afd5157

check = NonPassHashing("sha256")
print(check.check_file_hash(f1, "81cbae84a29ce7e770bf2bc7b178e50bda0ce8de6067aba661b0bc7b05b562f8"))  # -> True
print(check.check_file_hash(f1, "2c7498404231e3f980b42756c06de5f58cfde6e3e211a059f2e593380afd5157"))  # -> False

print(check.check_file_hash(f2, "81cbae84a29ce7e770bf2bc7b178e50bda0ce8de6067aba661b0bc7b05b562f8"))  # -> False
print(check.check_file_hash(f2, "2c7498404231e3f980b42756c06de5f58cfde6e3e211a059f2e593380afd5157"))  # -> True

# Therefore you can use this method to ensure integrity of your file, before downloading or distributing a file,
# you can provide the users with a hash of the file and after they download the file, they can check its hexdigest
# to ensure that the file hasn't been tampered with. I will also now be providing hexdigests of AuthAlpha.py in
# README.md.


print("------------------------------------------Hashes for AuthAlpha.py------------------------------------------")
for k in hash_list:

    hashed = NonPassHashing(k)
    h = hashed.generate_file_hash(f3)
    print(k, ":", h)
