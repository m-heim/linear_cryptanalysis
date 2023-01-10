import numpy as npy
import random
import math

random.seed("123", version=2)
sbox = random.sample(range(256), k=256)


def cipher(key: npy.array, pt: npy.array):
    size = math.ceil(pt.size / 8)
    output = pt.copy()
    output = npy.resize(output, size*8)
    print(str(output[0:8].shape) , str(key.shape))
    for i in range(size):
        save = output[:i*8]
        save = npy.append(save, npy.bitwise_xor(output[i*8:(i+1)*8] , key))
        save = npy.append(save, output[(i+1)*8:])
        output = save
        for b in range(8):
            output[i*8+b] = sbox[output[i*8+b]]
        save = output[:i*8]
        save = npy.append(save, npy.bitwise_xor(output[i*8:(i+1)*8] , key))
        save = npy.append(save, output[(i+1)*8:])
        output = save
    return output


def print_sbox():
    print(sbox)
    return


def find_good_choices():
    powers = [2 ** x for x in range(8)]
    good_choices = []
    for in1 in range(8):
        for in2 in list(range(8))[:in1] + list(range(8))[in1 + 1:]:
            for o in range(8):
                approx_true = 0
                for pt in range(255):
                    in_mask = powers[in1] + powers[in2]
                    out_mask = powers[o]
                    output = sbox[in_mask & pt]
                    output &= out_mask
                    if output == out_mask:
                        approx_true += 1
                print('for ' + str(in1) + ' ' + str(in2) + ' ' + str(o) +
                      ' the approximation is true ' + str(approx_true) + ' times')
            if approx_true >= 200 or approx_true <= 10:
                good_choices.append(
                    str(approx_true) + ' ' + str(in1) + ' ' + str(in2) + ' ' + str(o) + ' ' + '\n')
    return good_choices


def bruteforce(keys: list):
    pass


def main():
    key = npy.array(bytearray(b'\xB7\x62\xF1\x43\xC1\x93\x3A\x53'))
    data = npy.array(list(map(lambda c: ord(c), 'Hello World!')))
    print(str(len(key)), str(len(data)))
    print(cipher(key, data))
    #print(find_good_choices())
    #print(sbox)


if __name__ == '__main__':
    main()
