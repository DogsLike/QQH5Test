#coding=utf-8
from django.shortcuts import render
from django.http import HttpResponse

from Crypto.Cipher import AES
import binascii
from binascii import a2b_hex,b2a_hex
from urlparse import urlparse
import hmac
import urllib
import hashlib
import struct
import datetime
import time

AppId = "3875823424"
AppKey = "bQkrufwkbtYzsMFK"
AppDataKey = "DZubTFYXKyxgtWZJ"


# Create your views here.
def appSig(request):
	timeStamp = str(int(time.mktime(datetime.datetime.now().timetuple())));
	sig = Cryption.GetAppSig(AppId,timeStamp,"teeeeeee" ,AppKey,dataKey);
	response = HttpResponse(sig)
	response['Access-Control-Allow-Origin'] = "*"
	return response

def dataSig(request):
	if request.method=="POST":
		timeStamp = str(int(time.mktime(datetime.datetime.now().timetuple())));
		sig = Cryption.GetDataSig(request.POST["url"],request.method,request.POST,AppKey);
		response = HttpResponse(sig)
		response['Access-Control-Allow-Origin'] = "*"
		return response
	timeStamp = str(int(time.mktime(datetime.datetime.now().timetuple())));
	sig = Cryption.GetAppSig(request.POST["url"],request.method,request.POST,AppKey);
	response = HttpResponse(sig)
	response['Access-Control-Allow-Origin'] = "*"
	return response






class Cryption:
    
    __IgnoredSigName = ("appsig", "reqsig", "paysig")
    
    @staticmethod
    def GetAppSig (appId, time, nonce, appKey, dataKey):
        """获取应用签名
            appId: 应用Id
            time:  时间戳
            nonce: 随机串
            appKey: 应用密钥
            dataKey: 数据加密密钥
        """
        src = appId + "_" + time + "_" + nonce
        cipher = Cryption.GetCipherData(src, dataKey)        
        appKey += "&"
        appSig = Cryption.__GetSig(cipher, appKey)
        return appSig
    
    @staticmethod
    def GetDataSig (uri, method, queryMap, appKey):
        """生成请求或响应的数据的签名,返回请签名结果
            uri: 请求的Url
            method: 请求的方式，如GET,POST等
            queryMap: 查询参数对象
            appKey: 应用密钥
        """

        #keys = [m for m in queryMap.keys() if m != Cryption.__IgnoredSigName]
        #keys = [m for m in queryMap.keys() for i in range[0,len(Cryption.__IgnoredSigName)]]
        keys, tempKeys, isSig = queryMap.keys(), [], 0
        for m in range(len(keys)):
            isSig = 0
            for i in range(len(Cryption.__IgnoredSigName)):
                if(keys[m].lower() == Cryption.__IgnoredSigName[i].lower()):
                    isSig = isSig + 1
                    continue                 
            if isSig == 0:       
                tempKeys.append(keys[m])
        
        args = sorted(tempKeys)
        newArgs = []
        for k in range(len(tempKeys)): 
            newArgs.append(tempKeys[k] + "=" + str(queryMap[tempKeys[k]]))

        args = "&".join(newArgs)
        args = Cryption.UrlEncode(args, 1)
        
        tuple = urlparse(uri)
        path = Cryption.UrlEncode(tuple.path, 1)

        srcUrl = '%s&%s&%s' % (method.upper(), path, args)        
        appKey += "&"

        dataSig = Cryption.__GetSig(srcUrl, appKey)
        return dataSig  
    
    @staticmethod
    def __GetSig (rawData, appKey):
        """生成HMac-SHA1哈希码并返回
            rawData 生成HMac的源数据
            appKey 解钥
        """
        hashed = hmac.new(appKey, rawData, hashlib.sha1)
        sig = binascii.b2a_base64(hashed.digest())[:-1]
        sig = Cryption.UrlEncode(sig, 0)
        return sig;
    
    @staticmethod
    def GetCipherData (rawData, dataKey):
        """返回加密密文的Base64及UrlEncode后的串
            rawData: 需解密的明文
            appKey: 密钥
        """
        blockSize = 16
        count = len(rawData)
        #print "count:" , count
        padding = blockSize - count % blockSize
        if padding > 0:
            rawData = rawData + ('\0' * padding)
            #print "count2:", len(rawData)
        cryptor = AES.new(dataKey, AES.MODE_ECB)
        cipher = cryptor.encrypt(rawData)
        
        cipher = binascii.b2a_base64(cipher)[:-1]
        cipher = Cryption.UrlEncode(cipher, 0)
        return cipher

    @staticmethod
    def GetPlainData (cipherData, dataKey):
        """AES解密函数，返回解密明文
            cipherData: 密文数据
            dataKey: 数据密钥
        """
        plain = urllib.unquote(cipherData)
        plain = binascii.a2b_base64(plain)
        
        cryptor = AES.new(dataKey, AES.MODE_ECB)      
        plain = cryptor.decrypt(plain)
        plain = plain.rstrip('\0')
        return plain
    
    @staticmethod
    def UrlEncode(rawData,isSignSrc):
        result = rawData.encode('utf-8');
        print(result);
        result = urllib.quote(rawData,"");
        
        #if(isSignSrc != 1):
        #    result =  result.replace("%7E","~");            
        return result;