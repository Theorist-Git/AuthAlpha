from AuthAlpha import TwoFactorAuth
from AuthAlpha import PassHashing
from pyotp import TOTP

if __name__ == '__main__':
    crypt = TwoFactorAuth()

    """
    Classic OTP implementation:
    1. Generate static OTP of desired length.
    2. Store its hash, and verify it against user entered OTP.
    """
    otp_police = PassHashing("pbkdf2:sha256")
    static_otp = crypt.static_otp(otp_len=6)  # 123456
    print("Generated OTP:", static_otp)

    hashed_otp = otp_police.generate_password_hash(static_otp, cost=50000)
    user_otp = int(input("Enter OTP: "))
    if otp_police.check_password_hash(hashed_otp, user_otp):
        print("Correct OTP!")
    else:
        print("Incorrect OTP!")

    """
    TOTP implementation
    1. Use the totp method to generate a TOTP token (default length = 64) and a URL
       which can be used to make a scannable QR code.
       A tuple is returned like so: (token, URL)
    """

    secrets = crypt.totp(name="name", issuer_name="issuer_name")
    print("length 64 shared secret: ", secrets[0])
    print("URL object: ", secrets[1])

    """
    2. Use something like QRious to display your QR code: https://github.com/neocotic/qrious
    3. Verify OTPs using the shared secret.
    Use a 
    """

    print(crypt.verify(secrets[0], TOTP(secrets[0]).now()))  # Correct OTP
    print(crypt.verify(secrets[0], 123456))  # Incorrect OTP
