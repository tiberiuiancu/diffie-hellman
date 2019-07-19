import pickle
import hashlib

with open('sbox.pickle', 'rb') as f:
    sbox = pickle.load(f)

with open('sbox_reverse.pickle', 'rb') as f:
    sbox_reverse = pickle.load(f)

def subBytes(inp, reverse=False):
    ans = []

    for i in inp:
        if not reverse:
            ans.append(sbox[i])
        else:
            ans.append(sbox_reverse[i])

    return bytes(ans)

def shiftRows(inp, reverse=False):
    assert len(inp) == 16, 'shiftRows: argument should be of length 16'

    ans = list(inp)
    if not reverse:
        ans[1], ans[5], ans[9], ans[13] = ans[5], ans[9], ans[13], ans[1]
        ans[2], ans[6], ans[10], ans[14] = ans[10], ans[14], ans[2], ans[6]
        ans[3], ans[7], ans[11], ans[15] = ans[15], ans[3], ans[7], ans[11]
    else:
        ans[1], ans[5], ans[9], ans[13] = ans[13], ans[1], ans[5], ans[9]
        ans[2], ans[6], ans[10], ans[14] = ans[10], ans[14], ans[2], ans[6]
        ans[3], ans[7], ans[11], ans[15] = ans[7], ans[11], ans[15], ans[3]

    return bytes(ans)

# Galois Field Multiplication of two Bytes
def gmul(a, b):
    assert (type(a) == int and type(b) == int), 'gmul takes two bytes as arguments'

    p = 0

    for counter in range(8):
        if (b & 1) != 0:
            p ^= a
        b >>= 1

        hi_bit_set = (a & 0x80) != 0
        a <<= 1
        if hi_bit_set:
            a ^= 0x11B

    return p

def mixColumns(inp, reverse=False):
    cc = list(inp)
    ans = cc.copy()
    for c in range(4):
        if not reverse:
            ans[4 * c]     = gmul(2, cc[4 * c]) ^ gmul(3, cc[4 * c + 1]) ^ cc[4 * c + 2] ^ cc[4 * c + 3]
            ans[4 * c + 1] = cc[4 * c] ^ gmul(2, cc[4 * c + 1]) ^ gmul(3, cc[4 * c + 2]) ^ cc[4 * c + 3]
            ans[4 * c + 2] = cc[4 * c] ^ cc[4 * c + 1] ^ gmul(2, cc[4 * c + 2]) ^ gmul(3, cc[4 * c + 3])
            ans[4 * c + 3] = gmul(3, cc[4 * c]) ^ cc[4 * c + 1] ^ cc[4 * c + 2] ^ gmul(2, cc[4 * c + 3])
        else:
            ans[4 * c] = gmul(14, cc[4 * c]) ^ gmul(11, cc[4 * c + 1]) ^ gmul(13, cc[4 * c + 2]) ^ gmul(9, cc[4 * c + 3])
            ans[4 * c + 1] = gmul(9, cc[4 * c]) ^ gmul(14, cc[4 * c + 1]) ^ gmul(11, cc[4 * c + 2]) ^ gmul(13, cc[4 * c + 3])
            ans[4 * c + 2] = gmul(13, cc[4 * c]) ^ gmul(9, cc[4 * c + 1]) ^ gmul(14, cc[4 * c + 2]) ^ gmul(11, cc[4 * c + 3])
            ans[4 * c + 3] = gmul(11, cc[4 * c]) ^ gmul(13, cc[4 * c + 1]) ^ gmul(9, cc[4 * c + 2]) ^ gmul(14, cc[4 * c + 3])

    return bytes(ans)

def addRoundKey(inp, key):
    assert len(inp) == 16, 'addRoundKey: arguments should have length 16'

    return bytes([inp[i] ^ key[i] for i in range(16)])

def rotWord(inp):
    assert len(inp) == 4, 'rotWord: input should be of length 4'

    ans = list(inp)
    ans = [ ans[1], ans[2], ans[3], ans[0] ]
    return bytes(ans)

def XOR(*args):
    ans = [0, 0, 0, 0]
    for arg in args:
        assert len(arg) == 4, 'XOR: arguments should have length 4'

        ans[0] ^= arg[0]
        ans[1] ^= arg[1]
        ans[2] ^= arg[2]
        ans[3] ^= arg[3]

    return ans

def key_schedule(key, n_rounds, N=8):

    w = [ [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]] for i in range(N) ]

    rc = 1
    for i in range(N, (n_rounds + 1) * 4):
        if i % N == 0:
            rcon = [rc, 0, 0, 0]
            w.append(XOR(w[i - N], subBytes(rotWord(w[i - 1])), rcon))
            rc = 2 * rc if rc < 0x80 else (2 * rc) ^ 0x1B
        elif N > 6 and i % N == 4:
            w.append(XOR(w[i - N], subBytes(w[i - 1])))
        else:
            w.append(XOR(w[i - N], w[i - 1]))

    keys = []
    for i in range(n_rounds + 1):
        keys.append([])
        for c in range(4):
            keys[i].extend(w[4 * i + c])

        keys[i] = bytes(keys[i])

    return keys

class AES:
    def __init__(self, key, n_rounds=14):
        self.n_rounds = n_rounds

        if len(key) == 16:
            self.N = 4
        elif len(key) == 24:
            self.N = 6
        elif len(key) == 32:
            self.N = 8
        else:
            print('key length is not valid')
            exit(-1)

        self.keys = key_schedule(key, n_rounds, self.N)

    def encrypt(self, message):
        # pad message
        message += b'0' * ((16 - (len(message) % 16))%16)

        encrypted = b''

        # split message
        n_blocks = len(message) // 16
        for i in range(n_blocks):
            block = message[16 * i: 16 * (i + 1)]

            # initial round key add
            res = addRoundKey(block, self.keys[0])

            # n_rounds-1 rounds
            for round_no in range(1, self.n_rounds):
                res = subBytes(res)
                res = shiftRows(res)
                res = mixColumns(res)
                res = addRoundKey(res, self.keys[round_no])

            # final round
            res = subBytes(res)
            res = shiftRows(res)
            res = addRoundKey(res, self.keys[-1])

            encrypted += res

        return encrypted

    def decrypt(self, message):
        # considers message already padded
        assert (len(message) % 16 == 0), 'decrypt: length of message should be a multiple of 16'

        decrypted = b''

        # split message
        n_blocks = len(message) // 16
        for i in range(n_blocks):
            block = message[16 * i: 16 * (i + 1)]

            # final round
            res = addRoundKey(block, self.keys[-1])
            res = shiftRows(res, True)
            res = subBytes(res, True)

            for round_no in range(self.n_rounds - 1, 0, -1):
                res = addRoundKey(res, self.keys[round_no])
                res = mixColumns(res, True)
                res = shiftRows(res, True)
                res = subBytes(res, True)

            # initial round key add
            res = addRoundKey(res, self.keys[0])
            decrypted += res

        return decrypted

# basic key derivation function using sha-256
def key_derivation(x, salt, iterations=100000):
    return hashlib.pbkdf2_hmac('sha256', x, salt, iterations)


if __name__ == '__main__':

    key = b'a' * 32
    message = b'a' * 16
    print('encrypting message "' + message.decode('utf8') + '" with key "' + key.decode('utf8') + '"')

    aes = AES(b'a' * 32)
    enc_raw = aes.encrypt(message)
    enc = ' '.join([hex(i)[2:] for i in enc_raw]).upper()
    print('encrypted message:', enc)
    dec_raw = aes.decrypt(enc_raw)
    dec = ' '.join([hex(i)[2:] for i in dec_raw]).upper()
    print('decrypted message:', dec)
