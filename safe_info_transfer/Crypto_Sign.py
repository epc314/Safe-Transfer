import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import  PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Hash import SHA

# PRIVATE_KEY = '''-----BEGIN PRIVATE KEY-----
# MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANbmAO84SwWJAzMq
# El+FLJ8jxtzJazyy+0ih9+k0DzVVpcGEjcyj7L9otYZDndzq6X69YKRybcoWB0uQ
# aYAsPoa5kGR8OAOHISZ58csRDYETKa7ORSzX9VPFQj4c7Lm5mJgVwcNQGN2nxZhX
# ZN845bbXYr+rlGy7s+/PZzgKKq9VAgMBAAECgYAY0NaqyUVgjkHgVqtofGh6uBbu
# yBOqHsEF0i5er7RR5GIPxs7ZItTkBaNwrb49FKOCDzxpwQ0MmR6eiz6jnnhZwEcW
# sWy2n2Xn7ZURKw7YrGtNIfEXAxKlVSjRirIw9DXeRELWkHPNxxbHT2HA5iPA144o
# HDbN94pUP4EmHs0QwQJBAO2Co8ToQ9E6BjwJk4sQ4oJp7aXGhUD4+4p1MaiSsf3r
# H7NI2N+/YCTUFtmXlVvtAAya2XHgoilIOS3R3AL87E8CQQDnoLsEDOfkkNK6faM5
# IdZ4zPZKpvGY0u1YFvhPbAmudRlT0mSlCf1p5JIPoFt05hOAICFo02EWvZS+Ffsm
# dk0bAkA0vqBT6Ci3XCVqS84iQfurbo7CE9Yf2asy0lfW0c0JUJ/XlsPi3IMjap4w
# cENRCM7L/c9wRKx+cnWQQVyUpUptAkACvE05IQXkFynF9hHlbNbhmloWS55y1Zrj
# /XF1TqtWmh9wc/2oTVPm2kI3WQd7e/QjAT4jxMtSv25wSEYtEBydAkEAww9rZ+it
# kby/y0tXGg36g4J33TnQAw2jg9AQsb8cg5QWOaEdXERSC48+NWZExw61PXdBskiS
# pn6vHTs3dSCoHQ==
# -----END PRIVATE KEY-----'''
#
# PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
# MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDW5gDvOEsFiQMzKhJfhSyfI8bc
# yWs8svtIoffpNA81VaXBhI3Mo+y/aLWGQ53c6ul+vWCkcm3KFgdLkGmALD6GuZBk
# fDgDhyEmefHLEQ2BEymuzkUs1/VTxUI+HOy5uZiYFcHDUBjdp8WYV2TfOOW212K/
# q5Rsu7Pvz2c4CiqvVQIDAQAB
# -----END PUBLIC KEY-----'''

def rsa_encrypt(message, PUBLIC_KEY):
    public_key = RSA.importKey(PUBLIC_KEY)

    cipher = Cipher_pkcs1_v1_5.new(public_key)

    cipher_text = base64.b64encode(cipher.encrypt(message.encode())).decode()
    return cipher_text


def rsa_decrypt(cipher_text, PRIVATE_KEY):
    private_key = RSA.importKey(PRIVATE_KEY)

    cipher = Cipher_pkcs1_v1_5.new(private_key)

    retval = cipher.decrypt(base64.b64decode(cipher_text),'ERROR').decode('utf-8')
    return retval


def rsa_sign(message, PRIVATE_KEY):
    # PRIVATE_KEY = open('ChildSubject.txt').read()
    # print(PRIVATE_KEY)
    private_key = RSA.importKey(PRIVATE_KEY)

    data = SHA.new(message.encode())

    sig_pk = Signature_pkcs1_v1_5.new(private_key)
    sign = sig_pk.sign(data)
    result = base64.b64encode(sign)
    data = result.decode()
    return data

def rsa_checksign(message, data, PUBLIC_KEY):
    data = base64.b64decode(data)

    public_key = RSA.importKey(PUBLIC_KEY)

    sha_message = SHA.new(message.encode())

    signer = Signature_pkcs1_v1_5.new(public_key)
    result = signer.verify(sha_message, data)

    print(result)
if __name__ == '__main__':
    # cipher = rsa_encrypt('hello')
    # print(cipher)
    # print(rsa_decrypt(cipher))
    sign = rsa_sign('hello', PRIVATE_KEY)
    print(sign)
    rsa_checksign('hello', sign, PUBLIC_KEY)
    print(PRIVATE_KEY)