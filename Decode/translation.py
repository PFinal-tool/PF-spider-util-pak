# -*- coding: utf-8 -*-
# @Time    : 2023/5/11 11:01
# @Author  : PFinal南丞 <lampxiezi@163.com
# @File    : translation.py
# @Software: PyCharm
import argparse
import base64
import hashlib
import zlib

from Cryptodome.Cipher import AES
from prettytable import PrettyTable
from termcolor import colored


class Encode:
    """常用的加密"""

    def __init__(self, content, **other):
        self._content = content
        self._other = other
        self._encode = [
            "md5",
            "base64",
            "sha1",
            "sha256",
            "zlib"
        ]

    def main(self):

        """加密主函数"""
        table = PrettyTable()
        if self._other is not None:
            print(self._other)
            # 设置列名
            table.field_names = ["加密方式", "加密结果", "其他参数"]
            value = eval("self._encode_{}()".format(self._other['action']))
            table.add_row([self._other['action'], value, str(self._other)])
        else:
            # 设置列名
            table.field_names = ["加密方式", "加密结果"]
            for encode in self._encode:
                value = eval("self._encode_{}()".format(encode))  # 字符串转函数运行
                table.add_row([encode, value])

        print(colored(table, 'green'))

    def _encode_md5(self):
        """md5 encode"""
        hl = hashlib.md5()
        hl.update(self._content.encode('utf8'))
        return hl.hexdigest()

    def _encode_base64(self):
        """base64 encode"""
        return str(base64.b64encode(self._content.encode('utf8')), encoding='utf-8')

    def _encode_sha1(self):
        """"sha1 encode"""
        sha1 = hashlib.sha1()
        sha1.update(self._content.encode('utf8'))
        return sha1.hexdigest()

    def _encode_sha256(self):
        """"sha256 encode"""
        sha256 = hashlib.sha256()
        sha256.update(self._content.encode('utf8'))
        return sha256.hexdigest()

    def _encode_sha512(self):
        """sha512 encode"""
        sha512 = hashlib.sha512()
        sha512.update(self._content.encode('utf8'))
        return sha512.hexdigest()

    def _encode_zlib(self):
        """zlib encode"""
        return zlib.compress(self._content.encode('utf8'))

    def _encode_aes(self):
        """aes encode"""
        aes = AES.new(self._add_to_16(self._other['secret_key']), AES.MODE_CBC, self._add_to_16(self._other['iv']))
        encrypt_aes = aes.encrypt(self._add_to_16(self._content))
        encrypt_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码 返回
        # print(encrypt_text)
        return encrypt_text

    def _add_to_16(self, value):
        """Add a value to"""
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)


class Decode:
    """Decode"""

    def __init__(self, content, key="test"):
        self._content = content
        self._key = key
        self._decode = [
            "base64",
            "zlib"
        ]

    def main(self):
        """解码"""
        for decode in self._decode:
            try:
                result = eval("self._decode_{}()".format(decode))  # 字符串转函数运行
                print(colored(f"解码方式:{decode}，解码结果:{result}", 'green'))
                break
            except Exception:
                print(colored(f'【{decode}】解码失败，换一种 >>>', 'red'))
                continue

    def _decode_base64(self):
        return str(base64.b64decode(self._content.encode('utf8')), encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='爬虫小工具--加解密')
    # 添加参数
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', '--encode', nargs='?', help='常用的加密', default=['def'], required=False)

    group.add_argument('-d', '--decode', action='store_true', help='常用的解密')
    args = parser.parse_args()
    # print(args)
    # 打印结果
    if args.encode is None:
        # _key = input(colored("请输入加密的key:", 'green'))
        _content = input(colored("请输入要加密的字符串:", 'green'))
        ts = Encode(_content)
        ts.main()
    elif args.encode == 'aes':
        _key = input(colored("初始化密钥:", 'green'))
        _iv = input(colored("初始化向量:", 'green'))
        _content = input(colored("请输入要加密的字符串:", 'green'))
        ts = Encode(_content, secret_key=_key, action='aes', iv=_iv)
        ts.main()

    if args.decode:
        _content = input(colored("请输入要解密密的字符串:", 'green'))
        ts = Decode(_content)
        ts.main()
