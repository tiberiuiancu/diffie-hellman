import socket
import random
from os import urandom
from encryption import AES, key_derivation

HOST = '127.0.0.1'

p = 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559
g = 2
l = 256 # exponent bit size

def handle_connection(conn):
    # generate exponent
    x = random.randrange(2 ** (l - 1), 2 ** l)

    # send g^x mod p
    gxp = pow(g, x, p)
    gxp = gxp.to_bytes(2048 // 8, 'big')

    conn.sendall(gxp)

    # receive g^x mod p and compute d^(xa*xb) mod p
    data = conn.recv(1024)
    gxp = int.from_bytes(data, 'big')
    gxp = pow(gxp, x, p)
    gxp = gxp.to_bytes(gxp.bit_length()//8 + 1, byteorder='big')

    # generate random salt and send it
    salt = urandom(32)
    conn.sendall(salt)

    # get key
    key = key_derivation(gxp, salt)
    aes = AES(key)

    # get 'READY' message
    msg = conn.recv(1024)
    msg = aes.decrypt(msg)
    print(msg.decode('utf8'))


while True:
    try:
        with open('port.txt', 'r') as f:
            PORT = int(f.read())
        print('connecting to port ' + str(PORT))
        break
    except:
        continue

socketfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socketfd.connect((HOST, PORT))

handle_connection(socketfd)

socketfd.close()