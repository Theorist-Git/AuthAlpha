# Cryptography Methods
## Description

A python package that provides various hashing algorithms with support for user authentication.
Implementation of various encryption algorithms have also been provided. For every algorithm, potential flaws, uses
and best practices are discussed to the best of my knowledge.

## Getting Started

### Dependencies

* Argon2-cffi

* Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the python modules required.
```bash
$ pip install argon2-cffi
```


### Executing program

* Go to the tests directory and read and run tests for the algorithm you want to use. Each test is named like so:
```
Test_{algorithm}.py
```

## Author(s)

Contributor names and contact info
* Mayank vats : [Theorist-git](https://github.com/Theorist-Git)
  * Email: testpass.py@gmail.com

## Version History

* 0.1
    * Initial Release

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
Also, for every algorithm you add or change, make the changes to CryptographyMethods only. Appropriately change the comments too.
A test file strictly name like 'Test_{Algorithm}.py' (regex === ^Test_[a-zA-Z0-9_]*\.py$) should be created which demonstrates and tests the working of the algorithm.

## License

This project is licensed under the [GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/#) License - see LICENSE.txt file for more details.

Copyright (C) 2021 Mayank Vats
