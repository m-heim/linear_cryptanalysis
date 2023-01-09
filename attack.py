import numpy as npy
import random
import math


def sbox():
    random.seed("13e3252t6", version=2)
    return random.sample(range(256), k=256)


def shuffle(pt: list):
    random.seed("Jg2fe233gf32", version=2)
    return random.sample(pt, k=len(pt))


def cipher(key: npy.array, pt: npy.array):
    output = npy.array(pt.size)
    for i in range(math.ceil(pt.size / 8)):
        output = npy.bitwise_xor(output, key)
        output = npy.array(list(map(lambda b: sbox()[b], output)))
        output = npy.array(list(map(lambda i: )))
        output = npy.bitwise_xor(output, key)
    return output

def find_good_choices():
    powers = [2 ** x for x in range(8)]
    good_choices = []
    for in1 in range(8):
        for in2 in list(range(8))[:in1] + list(range(8))[in1 + 1:]:
            approx_true = 0
            for o in range(8):
                in_mask = powers[in1] + powers[in2]
                out_mask = powers[o]
                output = sbox()[in_mask]
                output &= out_mask
                if output == out_mask:
                    approx_true += 1
            print('for ' + str(in1) + ' ' + str(in2) +
                  ' the approximation is true ' + str(approx_true) + ' times')
            if approx_true >= 6 or approx_true <= 1:
                good_choices.append(
                    str(approx_true) + ' ' + str(in1) + ' ' + str(in2) + ' ' + str(o) + ' ' + '\n')
    return good_choices

def bruteforce(keys: list):
    pass


def main():
    key = npy.array(bytearray(b'\xB7\x62\xF1\x43\xC1\x93\x3A\x53'))
    data = npy.array(list(map(lambda c: ord(c), 'He1l9 World!')))
    print(str(data.size))
    print(cipher(key, data))

if __name__ == '__main__':
    main()
