from AuthAlpha.Non_Password_Hashing import NonPassHashing

if __name__ == '__main__':

    try:
        NonPassHashing("algo").supported_hash_methods
    except TypeError:
        print("Unsupported hash method")

    hash_list = NonPassHashing("sha512").supported_hash_methods

    test_str = "MAYANk VATS"

    for k in hash_list:
        hasher = NonPassHashing(k)
        h = hasher.generate_hash(test_str)
        print(k, ":", h)