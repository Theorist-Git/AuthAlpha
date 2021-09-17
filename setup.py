from distutils.core import setup

setup(
    name='AuthAlpha',
    packages=['AuthAlpha'],
    version='0.9a',
    license='GNU GPLv3',
    description='A python cryptography package to manage authentication and to ensure integrity of files.',
    author='Mayank Vats',
    author_email='testpass.py@gmail.com',
    url='https://github.com/Theorist-Git/AuthAlpha',
    download_url='https://github.com/user/reponame/archive/v_01.tar.gz',  # I explain this later on
    keywords=['AUTHENTICATION', 'CRYPTOGRAPHY', 'HASHING'],
    install_requires=[
        'argon2-cffi',
        'bcrypt',
        'scrypt'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        # "3 - Alpha", "4 - Beta" or "5 - Production/Stable" as the current state of your package
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: GNU GPLv3',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.9',
    ],
)