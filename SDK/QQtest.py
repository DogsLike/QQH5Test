# -*- coding: utf-8 -*-
from cryption import *

#开发者配置信息
appId, appKey, dataKey = "test", "testtesttesttest", "testtesttesttest"

print "*** Tencent QBH5Game Server SDK Test - Python ***"

#生成应用签名
time, nonce, targetSig = "1431054282", "teeeeeee", "joLIOEyEPAxeSW%2FEFa1kBjMF8uQ%3D"
appsig = Cryption.GetAppSig(appId, time, nonce, appKey, dataKey)
print "===GetAppSig:  {0} - {1}".format(appsig, targetSig)
assert appsig == targetSig


#加密数据
rawData, targetCipherData = "this is test Data我是中文0123456789", "vtooUMTy%2Besed7IzlS1uN0jfdUAcfXmlNdoLx6KOqZH2IS8AslxGAktdQDdWRq%2Ba" 
cipherData = Cryption.GetCipherData(rawData, dataKey)
print "===GetCipherData:  {0} - {1}".format(cipherData, targetCipherData)
assert cipherData == targetCipherData


#数据签名
uri, method, queryMap, targetDataSig = "http://cptest.cs0309.html5.qq.com/index?action=inquiry&data=" + cipherData + "&reqsig=abcdefg&appsig=012456", "GET", {"action":"inquiry", "data":cipherData, "reqsig":"abcdefg", "appsig": "012456"}, "Zwa0FvhCcgsEthm9x2S9ocZHS6k%3D"
datasig = Cryption.GetDataSig(uri, method, queryMap, appKey)
print "===GetDataSig: {0} - {1}".format(datasig, targetDataSig)
assert datasig == targetDataSig


#数据解密
plainData = Cryption.GetPlainData(cipherData, dataKey)
print "===GetPlainData: {0} - {1}".format(plainData, rawData)
assert plainData == rawData

#UrlEncode测试
import urllib
rawWord = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
result = UrlEncode(rawWord, 1)
print "===result: " + result
assert result == '%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D%7E'

raw = urllib.unquote(result)
print "===raw: " + raw
assert raw == rawWord