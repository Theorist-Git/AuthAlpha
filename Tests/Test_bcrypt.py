import time
from AuthAlpha.Password_Hashing import PassHashing

if __name__ == '__main__':

    bcrypt = PassHashing("bcrypt")

    """
    generate_hash_password(self, password: Any, prov_salt: Any = None) -> str
    Method will generate a argon2 hash
    Parameters are kept default, salt will be generated randomly.
    You can also provide your own salt but only with pbkdf2 and scrypt algorithms, but that is not recommended.
    """

    hashed = bcrypt.generate_password_hash("SuP#rS€cR€TPass")
    print(hashed)
    print("When pass is correct -> ", bcrypt.check_password_hash(hashed, "SuP#rS€cR€TPass"))  # Will return True
    print("When pass is not correct -> ", bcrypt.check_password_hash(hashed, "NotMyPassword"))  # Will return False

    # You can also provide you own cost parameter (COST_FACTOR for bcrypt), although the author has chosen
    # parameters sensible in general, everyone has different needs. You need to be careful here,
    # as a high  cost factor will take forever to generate and check hashes. See an example below.

    # For cost factor 16 in bcrypt:
    start = time.time()
    custom_hashed = bcrypt.generate_password_hash("SuP#rS€cR€TPass", cost=16)
    end = time.time()
    print("Custom Hash", custom_hashed)
    print("Time taken for 2^16 rounds = ", end - start)
    # 2^16 rounds take ~3.5 seconds on a machine with 11th Gen Intel(R) CORE(TM) i7-1165G7 @ 2.80 GHz

    print("When pass is correct -> ", bcrypt.check_password_hash(custom_hashed, "SuP#rS€cR€TPass"))  # Will return True
    print("When pass is not correct -> ", bcrypt.check_password_hash(custom_hashed, "NotMyPassword"))
    # Will return False
    salt = b"MayankVatsUCMMfestXXX."

    custom_salt = bcrypt.generate_password_hash("SuP#rS€cR€TPass", salt=salt)

    print("Hash with custom salt: ", custom_salt)

    print("When pass is correct (custom salt)-> ", bcrypt.check_password_hash(custom_salt, "SuP#rS€cR€TPass"))  # Will return True
    print("When pass is not correct (custom salt)-> ", bcrypt.check_password_hash(custom_salt, "SuP#rS€cR€TPassx"))
