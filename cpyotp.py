"""
CircuitPython-compatible TOTP/HOTP library
Based on pyotp but adapted for CircuitPython constraints
2025 (C) Devin Ranger           VERSION 1.0

== "PyOTP" Inspired CircuitPython OneTime Passcode Library ==

                    =Key Diffrences= 
* Removed Python stdlib dependencies: No urllib, secrets, unicodedata, etc.
* Custom Base32 implementation: CircuitPython doesn't have base64 module
* Custom HMAC-SHA1: Implemented from scratch since hmac module isn't available
* Simplified random generation: Uses urandom or os.urandom fallback
* Memory efficient: Reduced object creation and string operations
* No complex imports: Only uses time, hashlib, and basic built-ins
* Timing-safe comparison: Implemented without external dependencies
* URL encoding: Simple implementation without urllib

"""
import time
import hashlib
import binascii
try:
    from urandom import getrandbits
except ImportError:
    import os
    def getrandbits(bits):
        return int.from_bytes(os.urandom(bits // 8), 'big')

# Base32 implementation for CircuitPython
_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_BASE32_MAP = {_BASE32_ALPHABET[i]: i for i in range(len(_BASE32_ALPHABET))}

def base32_decode(s):
    """Decode base32 string to bytes"""
    s = s.upper().rstrip('=')
    # Pad to multiple of 8
    s += '=' * (-len(s) % 8)
    
    result = bytearray()
    buffer = 0
    bits_left = 0
    
    for char in s:
        if char == '=':
            break
        if char not in _BASE32_MAP:
            raise ValueError(f"Invalid base32 character: {char}")
        
        buffer = (buffer << 5) | _BASE32_MAP[char]
        bits_left += 5
        
        if bits_left >= 8:
            result.append((buffer >> (bits_left - 8)) & 0xFF)
            bits_left -= 8
    
    return bytes(result)

def base32_encode(data):
    """Encode bytes to base32 string"""
    if not data:
        return ""
    
    result = []
    buffer = 0
    bits_left = 0
    
    for byte in data:
        buffer = (buffer << 8) | byte
        bits_left += 8
        
        while bits_left >= 5:
            result.append(_BASE32_ALPHABET[(buffer >> (bits_left - 5)) & 0x1F])
            bits_left -= 5
    
    if bits_left > 0:
        result.append(_BASE32_ALPHABET[(buffer << (5 - bits_left)) & 0x1F])
    
    # Add padding
    while len(result) % 8 != 0:
        result.append('=')
    
    return ''.join(result)

def hmac_sha1(key, message):
    """HMAC-SHA1 implementation for CircuitPython"""
    if len(key) > 64:
        key = hashlib.sha1(key).digest()
    if len(key) < 64:
        key = key + b'\x00' * (64 - len(key))
    
    o_key_pad = bytes(k ^ 0x5C for k in key)
    i_key_pad = bytes(k ^ 0x36 for k in key)
    
    inner = hashlib.sha1(i_key_pad + message).digest()
    return hashlib.sha1(o_key_pad + inner).digest()

def strings_equal(s1, s2):
    """Timing-attack resistant string comparison"""
    if len(s1) != len(s2):
        return False
    
    result = 0
    for a, b in zip(s1.encode('utf-8'), s2.encode('utf-8')):
        result |= a ^ b
    return result == 0

def build_uri(secret, name, initial_count=None, issuer=None, 
              algorithm=None, digits=None, period=None, **kwargs):
    """Build OTP provisioning URI"""
    otp_type = "hotp" if initial_count is not None else "totp"
    
    # URL encode function (simplified)
    def quote(s):
        safe_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
        result = ""
        for char in s:
            if char in safe_chars:
                result += char
            else:
                result += f"%{ord(char):02X}"
        return result
    
    label = quote(name)
    if issuer:
        label = quote(issuer) + ":" + label
    
    params = [f"secret={secret}"]
    
    if issuer:
        params.append(f"issuer={quote(issuer)}")
    if initial_count is not None:
        params.append(f"counter={initial_count}")
    if algorithm and algorithm.lower() != "sha1":
        params.append(f"algorithm={algorithm.upper()}")
    if digits and digits != 6:
        params.append(f"digits={digits}")
    if period and period != 30:
        params.append(f"period={period}")
    
    for key, value in kwargs.items():
        params.append(f"{key}={value}")
    
    return f"otpauth://{otp_type}/{label}?{'&'.join(params)}"

class OTP:
    """Base class for OTP implementations"""
    
    def __init__(self, secret, digits=6, digest=hashlib.sha1, name=None, issuer=None):
        self.secret = secret
        self.digits = digits
        self.digest = digest
        self.name = name or "Secret"
        self.issuer = issuer
    
    def generate_otp(self, input_value):
        """Generate OTP for given input"""
        if isinstance(self.secret, str):
            key = base32_decode(self.secret)
        else:
            key = self.secret
        
        # Convert input to 8-byte big-endian
        input_bytes = input_value.to_bytes(8, 'big')
        
        # Generate HMAC
        if self.digest == hashlib.sha1:
            hmac_hash = hmac_sha1(key, input_bytes)
        else:
            raise ValueError("Only SHA1 is supported in CircuitPython")
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0F
        code = int.from_bytes(hmac_hash[offset:offset+4], 'big') & 0x7FFFFFFF
        
        return str(code % (10 ** self.digits)).zfill(self.digits)
    
    def verify(self, otp, input_value, valid_window=0):
        """Verify OTP with optional window"""
        for i in range(-valid_window, valid_window + 1):
            if strings_equal(otp, self.generate_otp(input_value + i)):
                return True
        return False

class TOTP(OTP):
    """Time-based One-Time Password"""
    
    def __init__(self, secret, digits=6, digest=hashlib.sha1, name=None, 
                 issuer=None, interval=30):
        super().__init__(secret, digits, digest, name, issuer)
        self.interval = interval
    
    def now(self):
        """Generate current TOTP"""
        return self.at(time.time())
    
    def at(self, for_time):
        """Generate TOTP for specific time"""
        return self.generate_otp(int(for_time) // self.interval)
    
    def verify(self, otp, for_time=None, valid_window=1):
        """Verify TOTP"""
        if for_time is None:
            for_time = time.time()
        return super().verify(otp, int(for_time) // self.interval, valid_window)
    
    def provisioning_uri(self, name=None, issuer_name=None, **kwargs):
        """Generate provisioning URI for QR codes"""
        return build_uri(
            self.secret,
            name or self.name,
            issuer=issuer_name or self.issuer,
            algorithm=self.digest.__name__.replace('sha', 'SHA') if hasattr(self.digest, '__name__') else 'SHA1',
            digits=self.digits,
            period=self.interval,
            **kwargs
        )

class HOTP(OTP):
    """HMAC-based One-Time Password"""
    
    def __init__(self, secret, digits=6, digest=hashlib.sha1, name=None, 
                 issuer=None, initial_count=0):
        super().__init__(secret, digits, digest, name, issuer)
        self.initial_count = initial_count
    
    def at(self, count):
        """Generate HOTP for specific counter value"""
        return self.generate_otp(count)
    
    def verify(self, otp, counter, valid_window=0):
        """Verify HOTP"""
        return super().verify(otp, counter, valid_window)
    
    def provisioning_uri(self, name=None, initial_count=None, issuer_name=None, **kwargs):
        """Generate provisioning URI for QR codes"""
        return build_uri(
            self.secret,
            name or self.name,
            initial_count=initial_count or self.initial_count,
            issuer=issuer_name or self.issuer,
            algorithm=self.digest.__name__.replace('sha', 'SHA') if hasattr(self.digest, '__name__') else 'SHA1',
            digits=self.digits,
            **kwargs
        )

def random_base32(length=16):
    """Generate random base32 string for secrets"""
    random_bytes = bytes(getrandbits(8) for _ in range(length))
    return base32_encode(random_bytes)[:length]

# Example usage and testing
if __name__ == "__main__":
    # Generate a random secret
    secret = random_base32(32)
    print(f"Secret: {secret}")
    
    # Create TOTP instance
    totp = TOTP(secret)
    current_otp = totp.now()
    print(f"Current TOTP: {current_otp}")
    
    # Verify the OTP
    is_valid = totp.verify(current_otp)
    print(f"Verification: {is_valid}")
    
    # Generate provisioning URI
    uri = totp.provisioning_uri(name="test@example.com", issuer_name="Test App")
    print(f"Provisioning URI: {uri}")
    
    # Create HOTP instance
    hotp = HOTP(secret)
    hotp_code = hotp.at(0)
    print(f"HOTP at counter 0: {hotp_code}")
