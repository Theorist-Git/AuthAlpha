from distutils.core import setup

setup(
    name='AuthAlpha',
    packages=['AuthAlpha'],
    version='0.7-alpha',
    license='GNU GPLv3',
    description='A python abstraction to generate and authenticate hashes of passwords and files of any type. The '
                'package can also be used to implement classic and Time Based OTPs.',
    author='Mayank Vats',
    author_email='dev-theorist.e5xna@simplelogin.com',
    url='https://github.com/Theorist-Git/AuthAlpha',
    download_url='https://github.com/Theorist-Git/AuthAlpha/archive/refs/tags/v0.6.3-alpha.tar.gz',
    keywords=['AUTHENTICATION', 'CRYPTOGRAPHY', 'HASHING'],
    install_requires=[
        'argon2-cffi',
        'bcrypt',
        'scrypt',
        'pyotp'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        # "3 - Alpha", "4 - Beta" or "5 - Production/Stable" as the current state of your package
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.9',
    ],
)
