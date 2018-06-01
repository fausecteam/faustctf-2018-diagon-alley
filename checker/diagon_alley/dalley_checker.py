from ctf_gameserver.checker import BaseChecker, OK, NOTWORKING, TIMEOUT, NOTFOUND
import socket
from struct import pack, unpack
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import binascii
from time import sleep
from nclib import Netcat, NetcatTimeout, NetcatError
import random
import string
import re
import hashlib

KEYSIZE = 2048

def p32(d):
    return pack('<I', d)

def u32(d):
    return unpack('<I', d)[0]

def p64(d):
    return pack('<Q', d)

def u64(d):
    return unpack('<Q', d)[0]
    
class Msg():
    def __init__(self, _id=0, seq=0, payload=''):
        self.len = 32 + len(payload)
        self.id = _id
        self.seq = seq
        self.payload_len = len(payload)
        self.payload = payload
        
    def encrypt(self, pub_key):
        payload = pub_key.encrypt(self.payload)
        self.len = 32 + len(payload)
        self.payload_len = len(payload)
        self.payload = payload

    def toString(self):
        buf = b''
        buf += p64(self.len)
        buf += p64(self.id)
        buf += p64(self.seq)
        buf += p64(self.payload_len)
        buf += self.payload
        return buf

class Remote():
    def __init__(self, host=None, port=None, sock=None, timeout=5):
        if sock is None:
            #self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #self.sock = nc = nclib.Netcat((host, port), verbose=True)
            self.sock = Netcat((host, port), verbose=False, raise_timeout=True)
            self.sock.settimeout(timeout)
        else:
            self.sock = sock
        self.id = 0
        self.seq = 0
        self.priv_key = None
        self.pub_key = None
        self.rand_gen = Random.new().read

    def getNextSeq(self):
        self.seq += 1
        return self.seq

    def connect(self, host, port):
        self.sock.connect((host, port))

    def initCon(self):
        self.genKey()
        exported_key = self.exportKey()
        #self.logger.debug("key_length: {}".format(len(exported_key)))
        #self.logger.debug("send: {}".format(p64(len(exported_key))))
        self.send(p64(len(exported_key)))
        #self.logger.debug(exported_key[:8])
        self.send(exported_key)
        #self.logger.debug("before recv")
        raw_key_length = u64(self.recv(8))
        #self.logger.debug("recvd length: {}".format(raw_key_length))
        raw_key = self.recv(raw_key_length)
        #self.logger.debug("recvd key")
        self.importKey(raw_key)

        msg = self.recv_enc()
        if msg.payload != b'Hello':
            raise RuntimeError("Init msg != Hello: %s" % msg.payload)
        self.id = msg.id
        self.seq = msg.seq

        #self.logger.debug('Got: {}'.format(msg.payload))
        self.send_enc(b'World')
        #self.logger.debug("send world")

    def send_enc(self, payload):
        msg = Msg(self.id, self.getNextSeq(), payload)
        msg.encrypt(self.pub_key)
        return self.send(msg.toString())

    def send(self, msg):
        sent = self.sock.send(msg)
        return sent
        #totalsent = 0
        #while totalsent < len(msg):
        #    sent = self.sock.send(msg[totalsent:])
        #    if sent == 0:
        #        raise RuntimeError("socket connection broken")
        #    totalsent = totalsent + sent
        #return sent

    def sendline(self, msg):
        return self.send(msg + '\n')

    def recv_enc(self):
        rsa_key = PKCS1_OAEP.new(self.priv_key, hashAlgo=Crypto.Hash.SHA)
        msg = Msg()
        msg.len = u64(self.recv(8))
        #self.logger.debug("msg.len {}".format(msg.len))
        msg.id = u64(self.recv(8))
        #self.logger.debug("msg.id {}".format(msg.id))
        msg.seq = u64(self.recv(8))
        #self.logger.debug("msg.seq {}".format(msg.seq))
        self.seq = msg.seq
        msg.payload_len = u64(self.recv(8))
        #self.logger.debug("msg.payload_len {}".format(msg.payload_len))
        raw_payload = self.recv(msg.payload_len)
        msg.payload = rsa_key.decrypt(raw_payload)
        return msg


    def recv(self, nbytes):
        #self.logger.debug("recving {} bytes".format(nbytes))
        chunk = self.sock.recv_exactly(nbytes)
        return chunk
        #chunks = []
        #bytes_recd = 0
        #while bytes_recd < nbytes:
        #    chunk = self.sock.recv(nbytes)
        #    if chunk == b'':
        #        raise RuntimeError("socket connection broken")
        #    chunks.append(chunk)
        #    bytes_recd = bytes_recd + len(chunk)
        #return b''.join(chunks)

    #def recvline(self):
    #    chunks = []
    #    current = ''
    #    while current != '\n':
    #        current = self.sock.recv(1)
    #        if current == b'':
    #            raise RuntimeError("socket connection broken")
    #        chunks.append(current)
    #    return b''.join(chunks)
    #
    #def recvuntil(self, needle):
    #    recvd = b''
    #    current = ''
    #    while needle not in recvd:
    #        current = self.sock.recv(1)
    #        if current == b'':
    #            raise RuntimeError("socket connection broken")
    #        recvd += current
    #    return recvd

    def genKey(self):
        self.priv_key = RSA.generate(KEYSIZE, self.rand_gen)

    def storeKey(self):
        with open('diagon_key.der', 'wb') as f:
            f.write(self.exportKey())

    def loadKey(self):
        with open('diagon_key.der', 'bb') as f:
            key = f.read()
            self.priv_key = RSA.importKey(key)

    def exportKey(self):
        pub_key = self.priv_key.publickey()
        return pub_key.exportKey(format='DER')

    def importKey(self, key):
        rsa_key = RSA.importKey(key)
        #self.logger.debug("N: {}".format(rsa_key.n))
        self.pub_key = PKCS1_OAEP.new(rsa_key, hashAlgo=Crypto.Hash.SHA)


class DiagonAlleyChecker(BaseChecker):
    def __init__(self, tick, team, service, ip):
        BaseChecker.__init__(self, tick, team, service, ip)
        self._tick = tick
        self._team = team
        self._service = service
        self._ip = ip
        self._port = 4441
        self._sock = None

    def check_service(self):
        try:
            shopName = self.randString(20)
            shopPass = self.randString(20)
            self._sock = self.connect()
            if self._sock == None:
                return TIMEOUT

            r = self._sock

            try:
                r.initCon()
            except RuntimeError as e:
                self.logger.debug("initCon: %s" % str(e))
                return NOTWORKING
            welcome(r)

            sig = self.randString(16)
            self.logger.debug("Creating signature {}".format(sig))
            signature(r, True, sig)

            readMenu(r)
            
            userPass = self.randString(16)
            self.logger.debug("Registering user with pass{}".format(userPass))
            uid = regUser(r, userPass)
            if uid < 0:
                return NOTWORKING
                
            readMenu(r)

            self.logger.debug("Logging in user {}".format(uid))
            if loginUser(r, uid, userPass) < 0:
                return NOTWORKING   

            readMenu(r)

            self.logger.debug("Creating shop {} with pass {}".format(shopName, shopPass))
            sid = createShop(r, shopName, shopPass)
            if sid < 0:
                return NOTWORKING   
                
            readMenu(r)

            self.logger.debug("Adding items")
            iids = []
            for i in range(5):
                iid = addItem(r, b"10", b"33", 'Funky_AAAAAAAAA/bin/sh_{}'.format(self.randString(5)).encode('utf-8'))
                if iid < 0:
                    return NOTWORKING   
                else:
                    self.logger.debug("Added item {}".format(iid))
                iids.append(iid)
                readMenu(r)
                
            #iid = addItem(r, b"10", b"33", b'A'*49+b'\0'+100*b'B')
            self.logger.debug("Buying items")
            for iid in iids:
               if buyItem(r, iid) < 0:
                    return NOTWORKING   
               else:
                   self.logger.debug("Bought item {}".format(iid))
               readMenu(r)
     
            leave(r)
            return OK
        except NetcatTimeout:
            return TIMEOUT
        except NetcatError:
            return NOTWORKING

    def place_flag(self):
        try:
            itemName = self.get_flag(self._tick).encode('utf-8')
            s = hashlib.sha1()
            s.update(itemName)
            flagHash = s.hexdigest().encode('utf-8')
            shopName = flagHash[:20]
            shopPass = flagHash[20:]
            self._sock = self.connect()
            if self._sock == None:
                return TIMEOUT

            r = self._sock

            try:
                r.initCon()
            except RuntimeError as e:
                self.logger.debug("initCon: %s" % str(e))
                return NOTWORKING
            welcome(r)

            signature(r)
            readMenu(r)
            
            userPass = self.randString(16)
            self.logger.debug("Registering user with pass{}".format(userPass))
            uid = regUser(r, userPass)
            if uid < 0:
                return NOTWORKING
                
            readMenu(r)

            self.logger.debug("Logging in user {}".format(uid))
            if loginUser(r, uid, userPass) < 0:
                return NOTWORKING   

            readMenu(r)

            self.logger.debug("Creating shop {} with pass {}".format(shopName, shopPass))
            sid = createShop(r, shopName, shopPass)
            if sid < 0:
                return NOTWORKING   
                
            readMenu(r)

            self.logger.debug("Adding items")
            for i in range(5):
                name = 'Magic_Be4ns_{}'.format(self.randString(5)).encode('utf-8')
                self.logger.debug("Addint item {}".format(name))
                iid = addItem(r, b"42", b"1337", name)
                if iid < 0:
                    return NOTWORKING   
                readMenu(r)
                
            self.logger.debug("Adding item {}".format(itemName))
            iid = addItem(r, b"4231337", b"1", itemName)
            if iid < 0:
                return NOTWORKING   
            readMenu(r)

            leave(r)
            return OK
        except NetcatTimeout:
            return TIMEOUT
        except NetcatError:
            return NOTWORKING

    def check_flag(self, tick):
        try:
            itemName = self.get_flag(self._tick).encode('utf-8')
            s = hashlib.sha1()
            s.update(itemName)
            flagHash = s.hexdigest().encode('utf-8')
            shopName = flagHash[:20]
            shopPass = flagHash[20:]


            self._sock = self.connect()
            if self._sock == None:
                return TIMEOUT
            r = self._sock

            try:
                r.initCon()
            except RuntimeError as e:
                self.logger.debug("initCon: %s" % str(e))
                return NOTWORKING
            welcome(r)

            signature(r)
            
            readMenu(r)
            shops = listShops(r)
            sid = -1
            self.logger.debug("Looking for shop {}".format(shopName.decode('utf-8')))
            for shop in shops:
                _id, name = re.findall(r'ID: (\d+) - NAME: ([\d\w\W]+)', shop)[0]
                if shopName.decode('utf-8') == name:
                    sid = int(_id)

            if sid == -1:
                return NOTFOUND

            userPass = self.randString(16)
            self.logger.debug("Registering user with pass {}".format(userPass))
            uid = regUser(r, userPass)
            if uid < 0:
                return NOTWORKING

            readMenu(r)

            self.logger.debug("Logging in user {} with pass {}".format(uid, userPass))
            if loginUser(r, uid, userPass) < 0:
                return NOTWORKING
            readMenu(r)

            self.logger.debug("Entering shop {} with pass".format(uid, shopPass))
            if enterShop(r, sid, shopPass) < 0:
                self.logger.debug("ERROR")
                return NOTWORKING
            else:
                self.logger.debug("Entered shop {}".format(sid))
            readMenu(r)

            
            self.logger.debug("Looking for item {}".format(itemName.decode('utf-8')))
            items = listItems(r)
            for item in items:
                _id, name = re.findall(r'ID: (\d+) - NAME: ([_\d\w\W]+)', item)[0]
                if itemName.decode('utf-8') == name:
                    leave(r)
                    return OK

            leave(r)
            return NOTFOUND

        except NetcatTimeout:
            return TIMEOUT
        except NetcatError:
            return NOTWORKING


    def connect(self):
        try:
            s = Remote(self._ip, self._port)
            return s
        except:
            return None

    def randString(self, N):
        return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N)).encode('utf-8')

def welcome(r):
    msg = r.recv_enc()
    return msg.payload.decode('utf-8')

def signature(r, do=False, sig=None):
    msg = r.recv_enc()
    if do:
        r.send_enc(b'y')
        msg = r.recv_enc()
        r.send_enc(sig)
    else:
        r.send_enc(b'n')

def readMenu(r):
    msg = r.recv_enc()
    return msg.payload.decode('utf-8') 

def listShops(r):
    r.send_enc(b'2')

    shops =  []
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    while payload.startswith('ID'):
        shops.append(payload)
        msg = r.recv_enc()
        payload = msg.payload.decode('utf-8')
    return shops

def regUser(r, pwd):
    r.send_enc(b'0')
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "User pwd" not in payload:
        print(payload)
        return -1
    r.send_enc(pwd)
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "with id" not in payload:
        return -1
    uid = int(payload.split('id ')[1])
    return uid

def loginUser(r, uid, pwd):
    r.send_enc(b'1')
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "User id" not in payload:
        return -1
    r.send_enc(str(uid).encode('utf-8'))
    
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "User pwd" not in payload:
        return -1
    r.send_enc(pwd)
    
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Successfully" not in payload:
        return -1
    uid = int(payload.split('user ')[1])
    return uid

def createShop(r, name, pwd):
    r.send_enc(b'4')
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Shop name" not in payload:
        return -1
    r.send_enc(name)
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Shop pwd" not in payload:
        return -1
    r.send_enc(pwd)
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "with id " not in payload:
        return -1
    sid = int(payload.split('id ')[1])
    return sid
    
def enterShop(r, sid, pwd):
    r.send_enc(b'3')
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Shop id" not in payload:
        return -1
    r.send_enc(str(sid).encode('utf-8'))
    
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Shop pwd" not in payload:
        return -1
    r.send_enc(pwd)
    
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Successfully" not in payload:
        return -1
    sid = int(payload.split('shop ')[1])
    return sid

def addItem(r, price, amount, name):
    r.send_enc(b'5')
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Item price" not in payload:
        return -1
    r.send_enc(price)
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Item amount" not in payload:
        return -1
    r.send_enc(amount)
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Item name" not in payload:
        return -1
    r.send_enc(name)

    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "with id " not in payload:
        return -1
    iid = int(payload.split('id ')[1])
    return iid


def buyItem(r, iid):
    r.send_enc(b'6')
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "Item id" not in payload:
        return -1
    r.send_enc(str(iid).encode('utf-8'))
    
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    if "with id " not in payload:
        return -1
    iid = int(payload.split('id ')[1])
    return iid
    
def listItems(r):
    r.send_enc(b'7')

    shops =  []
    msg = r.recv_enc()
    payload = msg.payload.decode('utf-8')
    while payload.startswith('ID'):
        shops.append(payload)
        msg = r.recv_enc()
        payload = msg.payload.decode('utf-8')
    return shops

def leave(r):
    r.send_enc(b'8')
    r.sock.shutdown()
    r.sock.close()

 


#r = Remote('localhost', 4441)
##r.connect('localhost', 4441)
#r.initCon()
#welcome(r)
#
#readMenu(r)
#shops = listShops(r)
#print("#########################")
#for shop in shops:
#    print(shop)
#print("#########################")
#
#uid = regUser(r, b"Super")
#print("#########################")
#print("User id {}".format(uid))
#print("#########################")
#
#readMenu(r)
#
#if loginUser(r, uid, b"Super") < 0:
#    print("ERROR")
#else:
#    print("#########################")
#    print("Logged in as {}".format(uid))
#    print("#########################")
#readMenu(r)
#
#sid = createShop(r, 'FOOBAR{}'.format(random.choice(range(0,1000))).encode('utf-8'), b'STRONG')
#if sid < 0:
#    print("ERROR")
#else:
#    print("#########################")
#    print("Created Shop {}".format(sid))
#    print("#########################")
#readMenu(r)
#
#shops = listShops(r)
#print("#########################")
#for shop in shops:
#    print(shop)
#print("#########################")
#
#if enterShop(r, sid, b'STRONG') < 0:
#    print("ERROR")
#else:
#    print("#########################")
#    print("Entered shop {}".format(sid))
#    print("#########################")
#readMenu(r)
#
#for i in range(10):
#    iid = addItem(r, b"10", b"50", 'WAND{}'.format(random.choice(range(0,1000))).encode('utf-8'))
#    if iid < 0:
#        print("ERROR")
#    else:
#        print("#########################")
#        print("Added item {}".format(iid))
#        print("#########################")
#    readMenu(r)
#    
#if buyItem(r, iid) < 0:
#    print("ERROR")
#else:
#    print("#########################")
#    print("Bought item {}".format(iid))
#    print("#########################")
#    
#readMenu(r)
#items = listItems(r)
#print("#########################")
#for item in items:
#    print(item)
#print("#########################")
#
#
#sleep(10)
#
