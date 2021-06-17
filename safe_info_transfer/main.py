import Crypto_Sign
import getKey
import AES
import os
def JIAcrypto(M, iv, Ypub_key):
    f = open('key.txt', 'w', encoding='utf-8')
    key = AES.GenPassword(16)
    f.write(key)
    # print('aes密钥为：'+ key + '\n')
    f.close()

    # pub_key, priv_key = rsa.newkeys(1024)

    f = open('Jpub_key.txt', 'r')
    Jpub_key = f.read()
    print('甲的公钥如下：\n')
    print(Jpub_key)
    f.close()

    f = open('Jpriv_key.txt', 'r')
    Jpriv_key = f.read()
    # print(priv_key)
    # print('甲私钥\n')
    f.close()

    ciphertext = str(AES.encrypt(M, key, iv), 'utf-8')
    print(ciphertext)
    cer = Crypto_Sign.rsa_sign(M, Jpriv_key)
    keycipher = Crypto_Sign.rsa_encrypt(key, Ypub_key)






    f = open('certificate.txt', 'w')
    f.write(cer)
    print('甲的证书如下：\n')
    print(cer)
    f.close()

    f = open('keycipher.txt', 'w')
    f.write(keycipher)
    print('甲的密钥加密后如下\n')
    print(keycipher)
    f.close()

    f = open('ciphertext.txt', 'w')
    f.write(ciphertext)
    print('加密成功')
    f.close()



def YIrecover(C, kc, Ypriv_key, iv, plain):
    key = Crypto_Sign.rsa_decrypt(kc, Ypriv_key)
    M = AES.decrypt(C, key, iv)


    text = input('恢复明文文件：')
    f = open(text, 'w')
    f.write(M)
    f.close()


    if(plain == M):
        print("success")
    else:
        print('failure')


def YIcheckCer(cer, Jpub_key, plain):
    print('乙方数字签名检查中...')
    Crypto_Sign.rsa_checksign(plain, cer, Jpub_key)




if __name__ == '__main__':
    cd = getKey.ReadKey()
    cd.getK()


    print('甲方进行加密...')

    text = input('输入明文文件：')
    f = open(text, 'r')
    plain = f.read()
    f.close()

    text = input('输入iv文件：')
    f = open(text, 'r')
    iv = f.read()
    f.close()

    text = input('输入乙公钥文件：')
    f = open(text, 'r')
    Ypub_key = f.read()
    f.close()

    JIAcrypto(plain, iv, Ypub_key)

    print('乙方进行文件恢复...')

    text = input('输入乙私钥文件：')
    f = open(text, 'r')
    Ypriv_key = f.read()
    f.close()

    text = input('输入密文文件：')
    f = open(text, 'r')
    ciphertext = f.read()
    f.close()

    text = input('输入恢复密钥文件：')
    f = open(text, 'r')
    keycipher = f.read()
    f.close()

    text = input('甲公钥文件：')
    f = open(text, 'r')
    Jpub_key = f.read()
    f.close()


    YIrecover(ciphertext, keycipher, Ypriv_key, iv, plain)


    text = input('输入数字证书文件：')
    f = open(text, 'r')
    cer = f.read()
    print('数字证书如下：')
    print(cer)
    f.close()

    YIcheckCer(cer, Jpub_key, plain)
    os.remove('Jpub_key.txt')
    os.remove('Jpriv_key.txt')
    os.remove('Ypub_key.txt')
    os.remove('Ypriv_key.txt')


