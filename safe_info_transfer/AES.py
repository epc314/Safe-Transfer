from Crypto.Cipher import AES
import random,string
from binascii import b2a_hex, a2b_hex


# 如果text不足16位的倍数就用空格补足为16位
def add_to_16(text):
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('utf-8')



# 加密函数
def encrypt(text, k, i):
    key = k.encode('utf-8')
    mode = AES.MODE_CBC
    iv = i.encode('utf-8')
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return b2a_hex(cipher_text)


# 解密后，去掉补足的空格用strip() 去掉
def decrypt(text, k, i):
    key = k.encode('utf-8')
    iv = i.encode('utf-8')
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')

def GenPassword(length):
    #随机出数字的个数
    numOfNum = random.randint(1,length-1)
    numOfLetter = length - numOfNum
    #选中numOfNum个数字
    slcNum = [random.choice(string.digits) for i in range(numOfNum)]
    #选中numOfLetter个字母
    slcLetter = [random.choice(string.ascii_letters) for i in range(numOfLetter)]
    #打乱这个组合
    slcChar = slcNum + slcLetter
    random.shuffle(slcChar)
    #生成密码
    genPwd = ''.join([i for i in slcChar])
    return genPwd


if __name__ == '__main__':

    f = open('key.txt', 'w', encoding='utf-8')
    key = GenPassword(16)
    f.write(key)
    print(key)
    f.close()

    f = open('iv.txt', 'r', encoding='utf-8')
    iv = f.read()
    print(iv)
    f.close()

    f = open('plain.txt', 'r', encoding='utf-8')
    plain = f.read()
    print(plain)
    f.close()


    e = str(encrypt(plain, key, iv), 'utf-8')  # 加密
    d = decrypt(e, key, iv)  # 解密
    print("加密:", e)
    print("解密:", d)