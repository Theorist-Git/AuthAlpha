import time
from AuthAlpha.Password_Hashing import PassHashing

if __name__ == '__main__':

    scrypt = PassHashing("scrypt")

    """
    generate_hash_password(self, password: Any, prov_salt: Any = None) -> str
    Method will generate a scrypt hash
    Parameters are kept default, salt will be generated randomly.
    You can also provide your own salt but only with pbkdf2 and scrypt algorithms, but that is not recommended.
    """

    hashed = scrypt.generate_password_hash("SuP#rS€cR€TPass")
    print(hashed)

    print("When pass is correct -> ", scrypt.check_password_hash(hashed, "SuP#rS€cR€TPass"))  # Will return True
    print("When pass is not correct -> ", scrypt.check_password_hash(hashed, "NotMyPassword"))  # Will return False

    # When you provide your own salt:

    hashed = scrypt.generate_password_hash("Secret", prov_salt="mayankvats".encode("utf-8"))
    print(hashed)
    print("When pass is correct -> ", scrypt.check_password_hash(hashed, "Secret"))

    # You can also provide you own cost parameter (number of iterations of scrypt), although the author has chosen
    # parameters sensible in general, everyone has different needs. You have to provide the number of iterations in the
    # power of 2, i.e the cost parameter you provide will be raised to the power of 2 automatically and used as the
    # number of iterations. The default parameter is 14, i.e number of iterations = 2^14 (16384). You need to be careful
    # here, as a high  cost factor will take forever to generate and check hashes. See an example below.

    start = time.time()
    custom_hashed = scrypt.generate_password_hash("SuP#rS€cR€TPass", cost=20)  # iterations = 2^20 === 1048576
    end = time.time()
    print("Custom Hash -> ", custom_hashed)
    print("TIme for 2^20 iterations: ", end - start)
    # 2^20 rounds take ~2 seconds on a machine with 11th Gen Intel(R) CORE(TM) i7-1165G7 @ 2.80 GHz.

    print("When pass is correct -> ", scrypt.check_password_hash(custom_hashed, "SuP#rS€cR€TPass"))  # Will return True
    print("When pass is not correct -> ",
          scrypt.check_password_hash(custom_hashed, "NotMyPassword"))  # Will return False
