import numpy as npy
import random


def sbox():
    random.seed(1000)
    box = list(range(256))
    random.shuffle(box)
    return box


def shuffle(pt: bytearray):
    random.seed(1000)
    random.shuffle(pt)


def xor(key: bytearray, pt: bytearray):
    ret = bytearray()
    for i, value in enumerate(pt):
        ret.append(pt[i] + key[i])
    return ret


def cipher(key: bytearray, pt: bytearray):
    sbox_baked = sbox()
    key1 = key[:4]
    key2 = key[4:]
    output = xor(key1, pt)
    for i, value in enumerate(output):
        output[i] = sbox_baked[value]
    shuffle(output)
    output = xor(key2, pt)
    return output


def main():
    key = bytearray(b'\x1A\x2B\31\x42\x53\x64\x75\x86')
    pt = bytearray('Hey!', 'utf-8')
    ct = cipher(key, pt)
    print(ct)


if __name__ == '__main__':
    main()
