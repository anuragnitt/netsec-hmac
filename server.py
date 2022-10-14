import socket
from select import select
from utils import PKE, MyHash, HMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HEADER_SIZE = 10

def server_socket(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen()
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

def on_new_client(c, pke):
    print('\n----- NEW CONNECT -----')
    send_data(c, pke.sharePubKey())
    print('Shared RSA public key')
    aes = recv_aes_key(c, pke)
    print('Received AES secret key')
    hmac = HMAC(pke.decrypt(recv_data(c)))
    print('Received HMAC secret key')
    cid = communicate(c, aes, hmac, b'', 0)
    print(f'----- CID: {cid.hex()} -----')

    return (aes, hmac, cid)

def communicate(client, aes, hmac, cid: bytes, _log=True):
    data = recv_data(client)
    mac = data[:MyHash.digest_size]
    data = data[MyHash.digest_size:]
    _mac = hmac.getMAC(data)

    if _log:
        if len(cid): print(f'\nCID: {cid.hex()}')
        print(f'ENC: {data.hex()}')
        print(f'MAC: {_mac.hex()}')

    assert _mac == mac
    msg = unpad(aes.decrypt(data), AES.block_size)

    return msg

def main():

    server_sock = server_socket('localhost', 3000)
    active_sockets = [server_sock]
    clients = {}

    pke = PKE()
    pke.randomKey(512)

    while True:
        try:
            read_sock, _, exc_sock = select(active_sockets, [], active_sockets)

            for sock in read_sock:
                if sock == server_sock:
                    client, _ = server_sock.accept()
                    active_sockets.append(client)
                    clients[client] = on_new_client(client, pke)

                else:
                    try:
                        msg = communicate(sock, *clients[sock])
                        print(f'RECEIVED: {msg.decode()}\n')

                    except AssertionError:
                        print('Message integrity check failed')
                    except ValueError:
                        pass
                    except Exception as e:
                        print(str(e))
                        sock.close()
                        active_sockets.remove(sock)
                        del clients[sock]

            for sock in exc_sock:
                active_sockets.remove(sock)
                del clients[sock]

        except Exception as e:
            print(str(e))
            break

    server_sock.close()

if __name__ == '__main__':
    main()
