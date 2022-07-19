from AuthAlpha.Password_Hashing import PassHashing

if __name__ == '__main__':

    argon = PassHashing("argon2id")

    """
    generate_hash_password(self, password: Any, prov_salt: Any = None) -> str
    Method will generate a argon2 hash
    Parameters are kept default, salt will be generated randomly.
    You can also provide your own salt but only with pbkdf2 and scrypt algorithms, but that is not recommended.
    """

    hashed = argon.generate_password_hash("SuP#rS€cR€TPass")
    print(hashed)
    print("When pass is correct -> ", argon.check_password_hash(hashed, "SuP#rS€cR€TPass"))  # Will return True
    print("When pass is not correct -> ", argon.check_password_hash(hashed, "NotMyPassword"))    # Will return False
