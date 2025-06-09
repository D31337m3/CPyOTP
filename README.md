# CPyOTP

A CircuitPython-compatible TOTP/HOTP (One-Time Password) library inspired by PyOTP, designed for microcontroller environments with limited resources.

## Features

- **No stdlib dependencies:** No use of `urllib`, `secrets`, or `unicodedata`.
- **Custom Base32 and HMAC-SHA1:** Implemented from scratch for compatibility.
- **Memory efficient:** Minimal object creation and string operations.
- **Timing-safe comparison:** Prevents timing attacks.
- **Simple random generation:** Uses `urandom` or `os.urandom`.
- **Provisioning URI builder:** For QR code generation.

## Usage

```python
from CPyOTP import TOTP, HOTP, random_base32

# Generate a random secret
secret = random_base32(32)

# Create a TOTP instance
totp = TOTP(secret)
otp = totp.now()
print("Current OTP:", otp)

# Verify OTP
print("Is valid:", totp.verify(otp))

# Generate provisioning URI
uri = totp.provisioning_uri(name="user@example.com", issuer_name="MyApp")
print("URI:", uri)

# HOTP example
hotp = HOTP(secret)
print("HOTP at counter 0:", hotp.at(0))
