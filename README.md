# Cryptography Methods
## Description

A python package that provides various hashing algorithms with support for user authentication. There are a lot of libraries
out there for implementing hashing algorithms but not many packages have built-in support for authentication, so I decided
to make one myself. Feel free to use it in your projects under the terms mentioned in license.txt.

Implementation of various encryption algorithms have also been provided. For every algorithm, potential flaws, uses
and best practices are discussed to the best of my knowledge.

## Getting Started

### Dependencies

* Argon2-cffi
* bcrypt
* scrypt


* Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the python modules required.
```bash
$ pip install argon2-cffi
```
```bash
$ pip install bcrypt
```
```bash
$ pip install scrypt
```

### Executing program

* Go to the tests directory and read and run tests for the algorithm you want to use. Each test is named like so:
```
Test_{algorithm}.py
```

### Supported hash types:
1. [argon2id](https://pypi.org/project/argon2-cffi/)
2. [PBKDF2:SHA family](https://docs.python.org/3/library/hashlib.html#pbkdf2_hmac)
3. [bcrypt](https://pypi.org/project/bcrypt/)
4. [scrypt](https://pypi.org/project/scrypt/)
## Author(s)

Contributor names and contact info
* Mayank vats : [Theorist-git](https://github.com/Theorist-Git)
  * Email: testpass.py@gmail.com

## Version History
See [commit history](https://github.com/Theorist-Git/Cryptography-Methods/commits/master)
* 0.4
  * Added support for scrypt
* 0.3
  * Added support for bcrypt
* 0.2
  * Added support for PBKDF2:SHA family
  * Enhanced and optimized code
* 0.1
    * Initial Release

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
Also, for every algorithm you add or change, make the changes to CryptographyMethods only. Appropriately change the comments too.
A test file strictly name like 'Test_{Algorithm}.py' (regex === ^Test_[a-zA-Z0-9_]*\.py$) should be created which demonstrates and tests the working of the algorithm.

## License

This project is licensed under the [GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/#) License - see LICENSE.txt file for more details.

Copyright (C) 2021 Mayank Vats
