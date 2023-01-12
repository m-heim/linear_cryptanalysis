import numpy as npy
import random
import math
import itertools
from collections import Counter

random.seed(123456)
sbox = random.sample(range(256), k=256)


def cipher(key: npy.array, pt: npy.array) -> npy.array:
    size = math.ceil(pt.size / 8)
    output = pt.copy()
    output.resize(size*8)
    for i in range(size):
        save = output[:i*8]
        save = npy.append(save, npy.bitwise_xor(output[i*8:(i+1)*8], key))
        save = npy.append(save, output[(i+1)*8:])
        output = save
        for b in range(8):
            output[i*8+b] = sbox[output[i*8+b]]
        save = output[:i*8]
        save = npy.append(save, npy.bitwise_xor(output[i*8:(i+1)*8], key))
        save = npy.append(save, output[(i+1)*8:])
        output = save
    return output


def print_sbox():
    print(sbox)
    return

def get_bits(number):
    ret = list(bin(number))[2:]
    ret.reverse()
    return ret + ['0'] * (8-len(ret))

def get_bit(number, i):
    return bool(int(get_bits(number)[i]))

def find_good_choices():
    powers = [2 ** x for x in range(8)]
    good_choices = []
    o_choices = set([])
    combinations = list(itertools.combinations(list(range(8)), 2))
    for i1, i2 in combinations:
        for o in range(8):
            approx_true = 0
            for pt in range(255):
                in_mask = powers[i1] + powers[i2]
                out_mask = powers[o]
                output = sbox[in_mask & pt]
                output &= out_mask
                # i1 xor i2 = o
                if bool(get_bit(pt,i1) ^ get_bit(pt,i2) == (output == out_mask)):
                    approx_true += 1
            
            if approx_true >= 220 or approx_true <= 30:
                good_choices.append(
                    (i1, i2, o, approx_true <= 30, approx_true))
                o_choices.add(o)
    return (good_choices, o_choices)


def bruteforce(keys: list):
    pass


def generate_block(bits: list, byte: int):
    block = npy.array(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00'))
    powers = [2 ** x for x in range(8)]
    block[byte] = powers[bits[0]]
    block[byte] += powers[bits[1]]
    return block


def generate_out_mask(bit: int, byte: int):
    block = npy.array(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00'))
    powers = [2 ** x for x in range(8)]
    block[byte] = powers[bit]
    return block


def main():
    key = npy.array(bytearray(b'\xB7\x62\xF1\x43\xC1\x93\x3A\x53'))
    full_block = npy.array(bytearray(b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'))
    empty_block = npy.array(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00'))
    data = npy.array(list(map(lambda c: ord(c), 'Hello World!')))
    print(str(len(key)), str(len(data)))
    print(cipher(key, data))
    choices, o_choices = find_good_choices()
    print(choices)
    results_even = []
    results_odd = []
    results_true = []
    i1_i2_true_o_false = []
    is_right = []
    buffer = []
    false_entries = []
    for byte in range(8):
        results_even.append([])
        results_odd.append([])
        results_true.append([])
        for i1, i2, o, must_xor, correlation in choices:
            mask = generate_block([i1, i2], byte)
            out_mask = generate_out_mask(o, byte)
            out = (cipher(key, mask) & out_mask)
            key_bits = list(bin(key[byte])[2:])
            key_bits.reverse()
            key_bits = key_bits + list('00000000')
            print(i1, i2 , o, list(bin(mask[byte])), list(bin(out_mask[byte])), out, key_bits, correlation)
            if correlation >= 230:
                # k1 ^ k2 ^ x1 ^ x2 ^ 1 ^ k3 = o
                if (all(out == out_mask) ^ 1 ^ 1 ^ 1) == 1:
                    print('pos odd')
                    results_odd.append((i1,i2,o))
                    is_right.append((int(key_bits[i1]) + int(key_bits[i2]) + int(key_bits[o])) % 2 == 1)
                    if not is_right[-1]:
                        false_entries.append(1)
                else:
                    print('pos even')
                    results_even.append((i1,i2,o))
                    is_right.append((int(key_bits[i1]) + int(key_bits[i2]) + int(key_bits[o])) % 2 == 0)
                    if not is_right[-1]:
                        false_entries.append(2)
            elif correlation < 30:
                # k1 ^ k2 ^ x1 ^ x2 ^ k3 = o
                if (all(out == out_mask) ^ 1 ^ 1) == 1:
                    print('neg odd')
                    results_odd.append((i1,i2,o))
                    is_right.append((int(key_bits[i1]) + int(key_bits[i2]) + int(key_bits[o])) % 2 == 1)
                    if not is_right[-1]:
                        false_entries.append(3)
                else:
                    print('neg even')
                    results_even.append((i1,i2,o))
                    is_right.append((int(key_bits[i1]) + int(key_bits[i2]) + int(key_bits[o])) % 2 == 0)
                    if not is_right[-1]:
                        false_entries.append(4)
            if not is_right[-1]:
                print('not correct')
    print('is true ' + str(is_right.count(True)))
    print('is false ' + str(is_right.count(False)))
    print(results_even, results_odd, Counter(false_entries))
    route = ["xor", "sbox", "xor"]


if __name__ == '__main__':
    main()
