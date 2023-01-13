from functools import reduce
import numpy as npy
import random
import math
import itertools
from collections import Counter

random.seed('TEST123', version=2)
sbox = random.sample(range(256), k=256)
sbox_4bit = random.sample(range(16), k=16)
inv_sbox = [sbox.index(i) for i in range(256)]
inv_sbox_4bit = [sbox_4bit.index(i) for i in range(16)]
print(sbox, inv_sbox)
powers = [2 ** x for x in range(8)]
high_corr = 190/256
low_corr = 70/256

in_1_out_1 = 0
in_2_out_1 = 1
in_3_out_1 = 2
in_0_out_1 = 3


def sbox_byte_with_4bit(b: int):
    out1 = sbox_4bit[b & int('0b00001111', 2)]
    out2 = sbox_4bit[b >> 4]
    return (out2 << 4) | out1


def inv_sbox_byte_with_4bit(b: int):
    out1 = inv_sbox[b & int('0b00001111', 2)]
    out2 = inv_sbox[b >> 4]
    return (out2 << 4) | out1


def cipher(key: npy.array, pt: npy.array) -> npy.array:
    new_size = math.ceil(pt.size / 8)
    output = pt.copy()
    output = npy.resize(output, new_size * 8)
    for i in range(new_size):
        save = npy.bitwise_xor(output[i*8:(i+1)*8], key)
        for b in range(8):
            save[b] = sbox[int(save[b])]
        output[i*8:(i+1)*8] = npy.bitwise_xor(save, key)
    return output

def cipher_4bit(key: npy.array, pt: npy.array) -> npy.array:
    new_size = math.ceil(pt.size / 8)
    output = pt.copy()
    output = npy.resize(output, new_size * 8)
    for i in range(new_size):
        save = npy.bitwise_xor(output[i*8:(i+1)*8], key)
        for b in range(8):
            save[b] = sbox_byte_with_4bit(save[b])
        output[i*8:(i+1)*8] = npy.bitwise_xor(save, key)
    return output

def decipher(key: npy.array, pt: npy.array) -> npy.array:
    new_size = math.ceil(pt.size / 8)
    output = pt.copy()
    output.resize(new_size*8)
    for i in range(new_size):
        save = npy.bitwise_xor(output[i*8:(i+1)*8], key)
        for b in range(8):
            save[b] = inv_sbox[int(save[b])]
        output[i*8:(i+1)*8] = npy.bitwise_xor(save, key)
    return output

def decipher_4bit(key: npy.array, pt: npy.array) -> npy.array:
    new_size = math.ceil(pt.size / 8)
    output = pt.copy()
    output = npy.resize(output, new_size * 8)
    for i in range(new_size):
        save = npy.bitwise_xor(output[i*8:(i+1)*8], key)
        for b in range(8):
            save[b] = inv_sbox_byte_with_4bit(save[b])
        output[i*8:(i+1)*8] = npy.bitwise_xor(save, key)
    return output


def get_bits(number) -> list[int]:
    ret = list(map(lambda b: int(b), bin(number)[2:]))
    ret.reverse()
    return ret + [0] * (8-len(ret))


def get_bit(number, i) -> bool:
    return bool(get_bits(number)[i])


def find_correlations() -> list:
    correlations = []
    for combinations in [itertools.combinations(range(8), i) for i in range(1, 4)]:
        for positions in combinations:
            for o_combinations in [itertools.combinations(range(8), i) for i in range(1, 3)]:
                for o_positions in o_combinations:
                    approx_true = 0
                    for pt in range(256):
                        in_mask = sum([powers[position]
                                      for position in positions])
                        out_mask = sum([powers[position]
                                       for position in o_positions])
                        output = sbox[pt | in_mask] & out_mask
                        # i1 xor i2 = o
                        val = 0
                        for position in positions:
                            val ^= get_bit(pt | in_mask, position)
                        for o_position in o_positions:
                            val ^= get_bit(output, o_position)
                        approx_true += val
                    correlations.append(
                        (positions, o_positions, approx_true / 256))
    return correlations


def find_correlations_4bit() -> list:
    correlations = []
    for combinations in [itertools.combinations(range(4), i) for i in range(1, 4)]:
        for positions in combinations:
            for o_combinations in [itertools.combinations(range(4), i) for i in range(1, 3)]:
                for o_positions in o_combinations:
                    approx_true = 0
                    for pt in range(16):
                        in_mask = sum([powers[position]
                                      for position in positions])
                        out_mask = sum([powers[position]
                                       for position in o_positions])
                        output = sbox[pt | in_mask] & out_mask
                        # i1 xor i2 = o
                        val = 0
                        for position in positions:
                            val ^= get_bit(pt | in_mask, position)
                        for o_position in o_positions:
                            val ^= get_bit(output, o_position)
                        approx_true += val
                    correlations.append(
                        (positions, o_positions, approx_true / 16))
    return correlations

def print_table(table: list[list]) -> None:
    for i in range(len(table)):
        print(table[i])
        print('\t', end='')
        print('')


def bruteforce(keys: list):
    pass


def generate_block(bits: list, byte: int):
    block = npy.array(
        bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00'), dtype=npy.uint8)
    for bit in bits:
        block[byte] += powers[bit]
    return block


def crack():
    key = npy.array(
        bytearray(b'\xB7\x62\xC1\x43\xA1\x93\x3A\x53'), dtype=npy.uint8)
    choices = find_correlations()
    results_even = []
    results_odd = []
    false_entries = []
    true_entries = []
    for byte in range(8):
        for positions, o_positions, correlation in filter(lambda c: c[2] <= low_corr or c[2] >= high_corr, choices):
            mask = generate_block(
                list(map(lambda p: p, positions)), byte)
            out_mask = generate_block(
                list(map(lambda p: p, o_positions)), byte)
            out = cipher(key, mask) & out_mask
            key_bits = get_bits(key[byte])
            print('BYTE: ', byte, 'POSITIONS', positions, o_positions, get_bits(mask[byte]), get_bits(
                out_mask[byte]), get_bits(out[byte]), key_bits, correlation)
            if correlation >= high_corr:
                # x1 ^ x2 ^ x3 ^ y1 = 1
                if reduce(lambda x, y: x ^ y, list(map(lambda p: get_bit(out[byte], p), o_positions)) + list(map(lambda p: get_bit(mask[byte], p), positions))):
                    print('pos even')
                    results_even.append((positions, o_positions))
                    val = 0
                    for position in positions:
                        val ^= key_bits[position]
                    for o_position in o_positions:
                        val ^= key_bits[o_position]
                    if not val:
                        true_entries.append(1)
                    else:
                        false_entries.append(1)
                        print('false')
                else:
                    print('pos odd')
                    results_odd.append((positions, o_positions))
                    val = 0
                    for position in positions:
                        val ^= key_bits[position]
                    for o_position in o_positions:
                        val ^= key_bits[o_position]
                    if val:
                        true_entries.append(2)
                    else:
                        false_entries.append(2)
                        print('false')
            elif correlation <= low_corr:
                # k1 ^ x1 ^ k2 ^ 1= o
                if not reduce(lambda x, y: x ^ y, list(map(lambda p: get_bit(out[byte], p), o_positions)) + list(map(lambda p: get_bit(mask[byte], p), positions))):
                    print('neg even')
                    results_odd.append((positions, o_positions))
                    val = 0
                    for position in positions:
                        val ^= key_bits[position]
                    for o_position in o_positions:
                        val ^= key_bits[o_position]
                    if not val:
                        true_entries.append(3)
                    else:
                        false_entries.append(3)
                        print('false')
                else:
                    print('neg odd')
                    results_even.append((positions, o_positions))
                    val = 0
                    for position in positions:
                        val ^= key_bits[position]
                    for o_position in o_positions:
                        val ^= key_bits[o_position]
                    if val:
                        true_entries.append(4)
                    else:
                        false_entries.append(4)
                        print('false')

    print(Counter(true_entries), Counter(false_entries))
    print(
        list(filter(lambda c: c[2] <= low_corr or c[2] >= high_corr, choices)))
    print(len(list(filter(
        lambda c: c[2] <= low_corr or c[2] >= high_corr, choices))) / len(choices))
    print(len(true_entries) / (len(true_entries) + len(false_entries)))


def crack_4bit():
    key = npy.array(
        bytearray(b'\xB7\x62\xC1\x43\xA1\x93\x3A\x53'), dtype=npy.uint8)
    choices = find_correlations()
    results_even = []
    results_odd = []
    false_entries = []
    true_entries = []
    for byte in range(8):
        for positions, o_positions, correlation in filter(lambda c: c[2] <= low_corr or c[2] >= high_corr, choices):
            mask = generate_block(
                list(map(lambda p: p, positions)), byte)
            out_mask = generate_block(
                list(map(lambda p: p, o_positions)), byte)
            out = cipher(key, mask) & out_mask
            key_bits = get_bits(key[byte])
            print('BYTE: ', byte, 'POSITIONS', positions, o_positions, get_bits(mask[byte]), get_bits(
                out_mask[byte]), get_bits(out[byte]), key_bits, correlation)
            if correlation >= high_corr:
                # x1 ^ x2 ^ x3 ^ y1 = 1
                if reduce(lambda x, y: x ^ y, list(map(lambda p: get_bit(out[byte], p), o_positions)) + list(map(lambda p: get_bit(mask[byte], p), positions))):
                    print('pos even')
                    results_even.append((positions, o_positions))
                    val = 0
                    for position in positions:
                        val ^= key_bits[position]
                    for o_position in o_positions:
                        val ^= key_bits[o_position]
                    if not val:
                        true_entries.append(1)
                    else:
                        false_entries.append(1)
                        print('false')
                else:
                    print('pos odd')
                    results_odd.append((positions, o_positions))
                    val = 0
                    for position in positions:
                        val ^= key_bits[position]
                    for o_position in o_positions:
                        val ^= key_bits[o_position]
                    if val:
                        true_entries.append(2)
                    else:
                        false_entries.append(2)
                        print('false')
            elif correlation <= low_corr:
                # k1 ^ x1 ^ k2 ^ 1= o
                if not reduce(lambda x, y: x ^ y, list(map(lambda p: get_bit(out[byte], p), o_positions)) + list(map(lambda p: get_bit(mask[byte], p), positions))):
                    print('neg even')
                    results_odd.append((positions, o_positions))
                    val = 0
                    for position in positions:
                        val ^= key_bits[position]
                    for o_position in o_positions:
                        val ^= key_bits[o_position]
                    if not val:
                        true_entries.append(3)
                    else:
                        false_entries.append(3)
                        print('false')
                else:
                    print('neg odd')
                    results_even.append((positions, o_positions))
                    val = 0
                    for position in positions:
                        val ^= key_bits[position]
                    for o_position in o_positions:
                        val ^= key_bits[o_position]
                    if val:
                        true_entries.append(4)
                    else:
                        false_entries.append(4)
                        print('false')

    print(Counter(true_entries), Counter(false_entries))
    print(
        list(filter(lambda c: c[2] <= low_corr or c[2] >= high_corr, choices)))
    print(len(list(filter(
        lambda c: c[2] <= low_corr or c[2] >= high_corr, choices))) / len(choices))
    print(len(true_entries) / (len(true_entries) + len(false_entries)))

def main():
    key = npy.array(
        bytearray(b'\xB7\x62\xF1\x43\xC1\x93\x3A\x53'), dtype=npy.uint8)
    data = npy.array(
        list(map(lambda c: ord(c), 'Hello World!')), dtype=npy.uint8)
    encrypted = cipher(key, data)
    print(encrypted)
    decrypted = decipher(key, encrypted)
    print(decrypted)
    print(list(data))
    print(find_correlations_4bit())
    #choices = find_correlations()
    # print('CHOICES', choices)
    crack()


if __name__ == '__main__':
    main()
