from AuthAlpha import TwoFactorAuth
from AuthAlpha import PassHashing
from pyotp import TOTP
"""
This file shows you how to implement OTP generation and verification 
using AuthAlpha.
"""

if __name__ == '__main__':
    crypt = TwoFactorAuth()
    while True:
        CHOICE = int(input("""
Press 1 for static OTP demonstration
Press 2 for TOTP demonstration  
Press 3 to QUIT                     : """))

        if CHOICE == 1:
            """
            Classic OTP implementation:
            1. Generate static OTP of desired length.
            2. Store its hash, and verify it against user entered OTP.
            """
            otp_police = PassHashing("pbkdf2:sha256")
            static_otp = crypt.static_otp(otp_len=6)  # 123456
            print("Generated OTP:", static_otp)

            hashed_otp = otp_police.generate_password_hash(static_otp, iterations=50000)
            print("Hashed OTP: ", hashed_otp, "\n")

            user_otp = int(input("Enter OTP to check against hash: "))

            if otp_police.check_password_hash(hashed_otp, str(user_otp)):
                print("Correct OTP!")
            else:
                print("Incorrect OTP!")

        elif CHOICE == 2:

            """
            TOTP implementation
            1. Use the totp method to generate a TOTP token (default length = 64) and a URL
               which can be used to make a scannable QR code.
               A tuple is returned like so: (token, URL)
            """

            secrets = crypt.totp(user_name="name", issuer_name="issuer_name")
            print("length 64 shared secret: ", secrets[0])
            print("URL object: ", secrets[1])

            """
            2. Use something like QRious to display your QR code: https://github.com/neocotic/qrious
            3. Verify OTPs using the shared secret.
            """

            print(crypt.verify(secrets[0], TOTP(secrets[0]).now()))  # Correct OTP
            print(crypt.verify(secrets[0], 123456))  # Incorrect OTP

            """
            4. A common problem you might face would be securely storing the shared secret in a database.
               AuthAlpha comes with in-built encryption and decryption using a password from v0.8.0a.
               You can use a user's password to encrypt their TOTP secret and keep it in your storage
               and decrypt it at login like so: 
            """

            PASSWORD = input("Enter password for encryption: ")
            shared_secret_enc = crypt.encrypt(PASSWORD.encode('utf-8'), secrets[0].encode('utf-8'))
            print("\nEncrypted Token: ", shared_secret_enc, "\n")

            PASSWORD = input("Enter password for decryption: ")
            try:
                shared_secret_dec = crypt.decrypt(PASSWORD.encode('utf-8'), shared_secret_enc)
                print("Here is your decrypted secret: ", shared_secret_dec)
            except ValueError:
                print('Incorrect password or otp, try again.')

        elif CHOICE == 3:
            break

        else:
            print("Invalid Input!!")
