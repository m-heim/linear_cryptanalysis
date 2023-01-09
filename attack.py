import numpy as npy
import random


def sbox():
    random.seed("J3e3232t6", version=2)
    return random.sample(range(256), k=256)


def sbox_round(block: list):
    box = sbox()
    ret = [0,0,0,0]
    for i in range(4):
        ret[i] = box[block[i]]
    return ret


def shuffle(pt: list):
    random.seed("Jg2fe233gf32", version=2)
    return random.sample(pt, k=len(pt))


def xor(key: list, block: list):
    print(key, block)
    ret = []
    for i in range(4):
        print((block[i] ^ key[i]))
        ret.append((block[i] ^ key[i]))
    return ret


def cipher(key: list, pt: list):
    key1 = key[:4]
    key2 = key[4:]
    output = xor(key1, pt)
    output = sbox_round(output)
    output = shuffle(output)
    print(output)
    output = xor(key2, output)
    print(output)
    return output


def main():
    key = list(b'\x17\x62\31\x43\x23\x74\x73\x36')
    print(key)
    pt = list(b'Hey!')
    print(pt)
    ct = cipher(key, pt)
    print(ct)


if __name__ == '__main__':
    main()
