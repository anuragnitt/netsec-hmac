import socket
from utils import PKE, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom

HEADER_SIZE = 10

def send_data(c, data: bytes):
    header = f'{hex(len(data))[2:]:>0{HEADER_SIZE}}'.encode()
    data = header + data
    c.send(data)

def recv_data(c):
    header = c.recv(HEADER_SIZE)
    data = c.recv(int(header.decode(), 16))
    return data

def share_aes_key(s, pke):
    aes_key = urandom(32)
    aes_iv = urandom(AES.block_size)
    aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    send_data(s, pke.encrypt(aes_key))
    send_data(s, pke.encrypt(aes_iv))

    return aes

def share_hmac_key(s, pke):
    hmac_key = urandom(16)
    hmac = HMAC(hmac_key)
    send_data(s, pke.encrypt(hmac_key))

    return hmac

def communicate(s, msg: bytes, aes, hmac, _log=True):
    tamper = False
    if msg.endswith(b'@'): tamper = True
    msg = aes.encrypt(pad(msg, AES.block_size))
    mac = hmac.getMAC(msg)

    if _log:
        print(f'ENC: {msg.hex()}')
        print(f'MAC: {mac.hex()}')

    if tamper: msg = b'\x00' + msg[1:]
    msg = mac + msg
    send_data(s, msg)

def main():

    s = socket.socket()
    s.connect(('localhost', 3000))

    pke = PKE()
    pke.recvPubKey(recv_data(s))
    print('\nReceived RSA public key')
    aes = share_aes_key(s, pke)
    print('Shared AES secret key')
    hmac = share_hmac_key(s, pke)
    print('Shared HMAC secret key')
    cid = urandom(3)
    communicate(s, cid, aes, hmac, 0)
    print(f'Client ID: {cid.hex()}')

    try:
        while True:
            msg = input('\nMESSAGE: ')
            if msg == 'exit': break
            communicate(s, msg.encode(), aes, hmac)

    except Exception as e:
        print(str(e))

    s.close()

if __name__ == '__main__':
    main()
