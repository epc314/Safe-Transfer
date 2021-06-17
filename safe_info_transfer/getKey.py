from OpenSSL import crypto
import rsa



class ReadKey(object):
    """用于读取密钥"""

    @staticmethod
    def get_public_key(cer_file_path):
        """
        从cer证书中提取公钥
        :param cer_file: cer证书存放的路径
        :return: 公钥
        """
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, open(cer_file_path, "rb").read())
        res = crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()).decode("utf-8")
        return res.strip()

    @staticmethod
    def get_private_key(pfx_file_path, password):
        """
        从pfx证书中提取私钥,如果证书已加密，需要输入密码
        :param pfx_file_path:pfx证书存放的路径
        :param password:证书密码
        :return:私钥
        """
        pfx = crypto.load_pkcs12(open(pfx_file_path, 'rb').read(), password)
        res = crypto.dump_privatekey(crypto.FILETYPE_PEM, pfx.get_privatekey())
        return res.strip()

    @staticmethod
    def getK():
        cd = ReadKey()
        with open('Ypub_key.txt','w') as f:
            f.write(cd.get_public_key('YIcer/YIpub.cer'))
            f.close()
        with open('Ypriv_key.txt','w') as f:
            f.write(cd.get_private_key('YIcer/YIpriv.pfx','123456').decode())
            f.close()
        with open('Jpub_key.txt','w') as f:
            f.write(cd.get_public_key('JIAcer/JIApub.cer'))
            f.close()
        with open('Jpriv_key.txt','w') as f:
            f.write(cd.get_private_key('JIAcer/JIApriv.pfx','666666').decode())
            f.close()

        # with open('TeacherRoot.pfx', "rb") as f:
        #     private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(f.read(), b"666666")
        # print(certificate.not_valid_after)


        #
        # with open('ChildSubject.pem', mode='rb') as privatefile:
        #     keydata = privatefile.read()
        # privkey = rsa.PrivateKey.load_pkcs1(keydata)


        # print(privkey)
