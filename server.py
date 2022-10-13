import socket
from utils import PKE, MyHash, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HEADER_SIZE = 10

def server_socket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    return s

def send_data(c, data: bytes):
    header = f'{hex(len(data))[2:]:>0{HEADER_SIZE}}'.encode()
    data = header + data
    c.send(data)

def recv_data(c):
    header = c.recv(HEADER_SIZE)
    data = c.recv(int(header.decode(), 16))
    return data

def recv_aes_key(c, pke):
    aes_key = pke.decrypt(recv_data(c))
    aes_iv = pke.decrypt(recv_data(c))
    aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)

    return aes

def interactive(client, aes, hmac):
    while True:
        try:
            data = recv_data(client)
            mac = data[:MyHash.digest_size]
            data = data[MyHash.digest_size:]
            _mac = hmac.getMAC(data)
            print(f'\nENC: {data.hex()}')
            print(f'MAC: {_mac.hex()}')
            assert _mac == mac
            msg = unpad(aes.decrypt(data), AES.block_size).decode()
            print(f'RECEIVED: {msg}\n')

        except AssertionError:
            print('Message integrity check failed')
        except Exception as e:
            print(str(e))
            break

def main():

    s = server_socket('localhost', 3000)
    pke = PKE()
    pke.getRandomKey(512)

    client, _ = s.accept()

    send_data(client, pke.sharePubKey())
    print('\nShared RSA public key')
    aes = recv_aes_key(client, pke)
    print('\nReceived AES secret key')
    hmac = HMAC(pke.decrypt(recv_data(client)))
    print('\nReceived HMAC secret key')

    interactive(client, aes, hmac)

    client.close()
    s.close()

if __name__ == '__main__':
    main()
