# [AuthAlpha]((https://pypi.org/project/AuthAlpha/))
[![Downloads](https://static.pepy.tech/personalized-badge/authalpha?period=total&units=international_system&left_color=black&right_color=orange&left_text=Downloads)](https://pepy.tech/project/authalpha)
## Description

A python abstraction to generate and authenticate hashes of passwords and files of any type.
The package can also be used to implement classic and Time Based OTPs.


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
Also, for every algorithm you add or change, appropriately change the comments too.
Add a file named like 'Test_{Algorithm}.py' under 'Tests' directory to demonstrate and test the working of the algorithm.

## Author(s)

Contributor names and contact info
* Mayank vats : [Theorist-git](https://github.com/Theorist-Git)
  * Email: dev-theorist.e5xna@simplelogin.com

## Version History
See [commit history](https://github.com/Theorist-Git/Cryptography-Methods/commits/master)
* **0.8.2a**
  * Introduced stricter type casting to PassHashing class resulting in cleaner code
    and lower chances of runtime errors.
* **0.8.1a**
  * pbkdf2 code optimizations, re-wrote tests.
* **0.8.0a**
  * Added Encryption and Decryption support in OTPMethods.py for TOTP tokens.
* **0.7.0a**
  * Added OTP methods, updated email and README.md.
* **0.6.3a**
  * Added project to PyPI.
* **0.6.2a**
  *  Fixed scrypt non-custom-hash, split the class into two to improve performance
* **0.6.1a**
  * Minor Code Optimizations 
* **0.6a**
  * Added functionality to generate and check hashes of files.
  * AuthAlpha.py SHA256 hash of this commit are in the file Integrity.txt. It will be updated with every commit.
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
**TBD**
In the meanwhile you can review the code, it is fully commented.

## PostScriptrum

* After downloading, make sure you have the un-tampered files with you, check Integrity.txt to check the hashes of the
AuthAlpha file match with the ones you have. If they do not match, contact the author(s) immediately at
dev-theorist.e5xna@simplelogin.com.

## License

This project is licensed under the [GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/#) License - see LICENSE.txt file for more details.

Copyright (C) 2021-2022 Mayank Vats
