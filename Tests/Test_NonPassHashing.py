from AuthAlpha.Non_Password_Hashing import NonPassHashing

if __name__ == '__main__':
    hash_list = NonPassHashing("algo").supported_hash_methods
    print("List of supported hashes: ", hash_list)

    test_str = "MAYANk VATS"

    for k in hash_list:
        hasher = NonPassHashing(k)
        h = hasher.generate_hash(test_str)
        print(k, ":", h)