from AuthAlpha.Non_Password_Hashing import NonPassHashing

hash_list = NonPassHashing("algo").supported_hash_methods
print("List of supported hashes: ", hash_list)

license_path = "/home/theorist/Desktop/Programming/python/AuthAlpha/Integrity.txt"
pass_hashing = "/home/theorist/Desktop/Programming/python/AuthAlpha/AuthAlpha/Password_Hashing.py"
non_pass_hashing = "/home/theorist/Desktop/Programming/python/AuthAlpha/AuthAlpha/Non_Password_Hashing.py"
otp_methods = "/home/theorist/Desktop/Programming/python/AuthAlpha/AuthAlpha/OTPMethods.py"

hashed = NonPassHashing('sha256')
print("License.txt SHA256 hash", hashed.generate_file_hash(license_path))

# SHA256 hash of license: 81cbae84a29ce7e770bf2bc7b178e50bda0ce8de6067aba661b0bc7b05b562f8

print(hashed.check_file_hash(license_path, "81cbae84a29ce7e770bf2bc7b178e50bda0ce8de6067aba661b0bc7b05b562f8"))
# ↑ True
print(hashed.check_file_hash(license_path, "2c7498404231e3f980b42756c06de5f58cfde6e3e211a059f2e593380afd5157"))
# ↑ False

# Therefore you can use this method to ensure integrity of your file, before downloading or distributing a file,
# you can provide the users with a hash of the file, and after they download the file, they can check its hash
# to ensure that the file hasn't been tampered with. I will also now be providing SHA256 hashes of relavent
# files in Integrity.txt file.

f = open(r"/home/theorist/Desktop/Programming/python/AuthAlpha/Integrity.txt", "w")
updated_hash = (
    "Hash for Password_Hashing.py:\n"
    f"sha256 : {NonPassHashing('sha256').generate_file_hash(pass_hashing)}"
    "\n----------------------------------------------------------------------------"
    "\n\n"
    "Hash for Non_Password_Hashing.py:\n"
    f"sha256 : {NonPassHashing('sha256').generate_file_hash(non_pass_hashing)}"
    "\n----------------------------------------------------------------------------"
    "\n\n"
    "Hash for OTPMethods.py:\n"
    f"sha256 : {NonPassHashing('sha256').generate_file_hash(otp_methods)}"
    "\n----------------------------------------------------------------------------"
)
f.write(updated_hash)
f.close()

print("--------------------------------------Hashes for Password_Hashing.py----------------------------------------")
for k in hash_list:
    hashed = NonPassHashing(k)
    h = hashed.generate_file_hash(pass_hashing)
    print(k, ":", h)

print("--------------------------------------Hashes for Non_Password_Hashing.py--------------------------------------")
for k in hash_list:
    hashed = NonPassHashing(k)
    h = hashed.generate_file_hash(non_pass_hashing)
    print(k, ":", h)

print("--------------------------------------Hashes for OTPMethods.py--------------------------------------")
for k in hash_list:
    hashed = NonPassHashing(k)
    h = hashed.generate_file_hash(otp_methods)
    print(k, ":", h)
