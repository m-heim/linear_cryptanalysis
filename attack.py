import numpy as npy
import random


def sbox():
    random.seed("13e3252t6", version=2)
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
    ret = []
    for i in range(4):
        ret.append((block[i] ^ key[i]))
    return ret


def cipher(key: list, pt: list):
    key1 = key[:4]
    key2 = key[4:]
    output = xor(key1, pt)
    output = sbox_round(output)
    output = shuffle(output)
    output = xor(key2, pt)
    return output


def main():
    key = list(b'\xB7\x62\xF1\x43\xC1\x93\x3A\x53')
    print(key)
    #pt = list(b'Hey!')
    #print(pt)
    #ct = cipher(key, pt)
    #print(ct)
    test_pt = list(b'\x00\x00\x00\x01')
    print(cipher(key, test_pt))
    powers = [2 ** x for x in range(8)]
    matrix = []
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
            print('for ' + str(in1) + ' ' + str(in2) + ' the approximation is true ' + str(approx_true) + ' times')
            if approx_true >= 6 or approx_true <= 1:
                good_choices.append(str(approx_true) + ' ' + str(in1) + ' ' + str(in2) + ' ' + str(o) + ' ' + '\n')
    print(good_choices)



if __name__ == '__main__':
    main()
