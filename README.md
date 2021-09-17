# AuthAlpha
## Description

A python package that provides various hashing algorithms with support for user authentication. There are a lot of libraries
out there for implementing hashing algorithms but not many packages have built-in support for authentication, so I decided
to make one myself. Feel free to use it in your projects under the terms mentioned in license.txt. This package can also
be used to generate and check hashes for all types of files. Hope this package helps you!


## Getting Started

### Installation:

* Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the python modules required.
```bash
$ pip install AuthAlpha
```

### Usage:
* See the [Tests](https://github.com/Theorist-Git/AuthAlpha/tree/master/Tests)
directory to see the detailed usage of every class and method.
* [Authalpha.py](https://github.com/Theorist-Git/AuthAlpha/blob/master/AuthAlpha.py) file contains the workarounds for the possible errors
you might encounter.

### Supported hash types:

#### For passwords:
1. [argon2id](https://en.wikipedia.org/wiki/Argon2)
2. [PBKDF2:SHA family](https://en.wikipedia.org/wiki/PBKDF2)
3. [bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
4. [scrypt](https://en.wikipedia.org/wiki/Scrypt)

#### For Generating File Hashes:
1. [SHA1](https://en.wikipedia.org/wiki/SHA-1)
2. [SHA2](https://en.wikipedia.org/wiki/SHA-2)
3. [SHA3](https://en.wikipedia.org/wiki/SHA-3)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
Also, for every algorithm you add or change, make the changes to AuthAlpha only. Appropriately change the comments too.
A test file strictly name like 'Test_{Algorithm}.py' should be created which demonstrates and tests the working of the algorithm.

## Author(s)

Contributor names and contact info
* Mayank vats : [Theorist-git](https://github.com/Theorist-Git)
  * Email: testpass.py@gmail.com

## Version History
See [commit history](https://github.com/Theorist-Git/Cryptography-Methods/commits/master)
* **0.8a**
  *  Fixed scrypt non-custom-hash, split the class into two to improve performance
* **0.7a**
  * Minor Code Optimizations 
* **0.6a**
  * Added functionality to generate and check hashes of files.
  * AuthAlpha.py hexdigests of this commit are in the file Integrity.txt. It will be updated with every commit.
* **0.5a**
  * Added customizable cost parameters for bcrypt, scrypt and PBKDF2:SHA family.
* **0.4a**
  * Added support for scrypt
* **0.3a**
  * Added support for bcrypt
* **0.2a**
  * Added support for PBKDF2:SHA family
  * Enhanced and optimized code
* **0.1a**
    * Initial Release

* **P.S: 0.1a means version 0.1 alpha**

## Documentation
~**TBD**~
In the meanwhile you can review the code, it is fully commented.

## PostScriptrum

* After downloading, make sure you have the un-tampered files with you, check Integrity.txt to check the hashes of the
AuthAlpha file match with the ones you have. If they do not match, contact the author(s) immediately at
testpass.py@gmail.com.

## License

This project is licensed under the [GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/#) License - see LICENSE.txt file for more details.

Copyright (C) 2021 Mayank Vats
