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

def interactive(s, aes, hmac):
    try:
        while True:
            msg = input('\nMESSAGE: ')
            if msg == 'exit': break
            tamper = False
            if msg.endswith('0'): tamper = True

            msg = aes.encrypt(pad(msg.encode(), AES.block_size))
            mac = hmac.getMAC(msg)
            print(f'ENC: {msg.hex()}')
            print(f'MAC: {mac.hex()}')
            if tamper: msg = b'\x00' + msg[1:]
            msg = mac + msg
            send_data(s, msg)

    except Exception as e:
        print(str(e))

def main():

    s = socket.socket()
    s.connect(('localhost', 3000))

    pke = PKE()
    pke.recvPubKey(recv_data(s))
    print('\nReceived RSA public key')
    aes = share_aes_key(s, pke)
    print('\nShared AES secret key')
    hmac = share_hmac_key(s, pke)
    print('\nShared HMAC secret key')

    interactive(s, aes, hmac)
    s.close()

if __name__ == '__main__':
    main()
