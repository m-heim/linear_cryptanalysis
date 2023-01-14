from functools import reduce
import numpy as npy
import random
import math
import itertools
from collections import Counter

sbox_maximum_width = 8
random.seed('543', version=2)
sboxes = [random.sample(range(2 ** i), k=2 ** i)
          for i in range(sbox_maximum_width)]
inv_sboxes = [[sboxes[i].index(j) for j in range(
    len(sboxes[i]))] for i in range(len(sboxes))]
powers = [2 ** x for x in range(8)]
low_corr, high_corr = 80/256, 180/256


def sbox_byte(b: int, sbox_size: int = 4):
    if 8 / sbox_size != int(8 / sbox_size):
        raise ValueError

    sbox_amount = int(8 / sbox_size)
    sbox = sboxes[sbox_size]
    ciphertext = 0
    for i in range(sbox_amount):
        ciphertext += sbox[b &
                           int('0b0000' + '1' * sbox_size, 2)] << i * sbox_size
        b >> i * sbox_size
    return ciphertext


def inv_sbox_byte(b: int, sbox_size: int = 4):
    if 8 / sbox_size != int(8 / sbox_size):
        raise ValueError

    sbox_amount = int(8 / sbox_size)
    inv_sbox = inv_sboxes[sbox_size]
    ciphertext = 0
    for i in range(sbox_amount):
        ciphertext += inv_sbox[b & int('0b0000' + '1' *
                                       sbox_size, 2)] << i * sbox_size
        b >> i * sbox_size
    return ciphertext


def number_from_powers(bits: list[int]):
    return sum(map(lambda p: powers[p], bits))


def print_table(table: list[list]) -> None:
    for i in range(len(table)):
        print(table[i])
        print('\t', end='')
        print('')
    return


def filter_list(input, filter):
    ret = []
    for i in range(len(input)):
        if filter[i]:
            ret.append(input[i])
    return ret


def bruteforce(keys: list):
    pass


def xor_list(lst: list):
    val = 0
    for e in list(lst):
        val ^= e
    return val


def xor_positions(number: int, bits: list[int]):
    number_as_bit_list = get_bits(number)
    return xor_list([number_as_bit_list[b] for b in bits])


def generate_block(bits: list, byte: int):
    block = npy.array(
        bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00'), dtype=npy.uint8)
    block[byte] = int(number_from_powers(bits))
    return block


def filter_choices(choices: list):
    return list(filter(lambda c: c[2] <= low_corr or c[2] >= high_corr, choices))


def get_bits(number: int) -> list[int]:
    ret = list(map(lambda b: int(b), bin(number)[2:]))
    ret.reverse()
    return ret + [0] * (8-len(ret))


def get_bit(number: int, i: int) -> bool:
    return bool(get_bits(number)[i])


def cipher(key: npy.array, pt: npy.array, sbox_width: int = 4) -> npy.array:
    new_size = math.ceil(pt.size / 8)
    output = pt.copy()
    output = npy.resize(output, new_size * 8)
    for i in range(new_size):
        save = npy.bitwise_xor(output[i*8:(i+1)*8], key)
        for b in range(8):
            save[b] = sbox_byte(int(save[b]), sbox_width)
        output[i*8:(i+1)*8] = npy.bitwise_xor(save, key)
    return output


def decipher(key: npy.array, pt: npy.array, sbox_width: int = 4) -> npy.array:
    new_size = math.ceil(pt.size / 8)
    output = pt.copy()
    output.resize(new_size*8)
    for i in range(new_size):
        save = npy.bitwise_xor(output[i*8:(i+1)*8], key)
        for b in range(8):
            save[b] = inv_sbox_byte(int(save[b]), sbox_width)
        output[i*8:(i+1)*8] = npy.bitwise_xor(save, key)
    return output


def find_correlations(sbox_width: int = 4, in_amount: int = 3, out_amount: int = 2) -> list:
    correlations = []
    for positions_len_i in [list(itertools.combinations(range(sbox_width), i)) for i in range(1, 5)]:
        for o_positions_len_i in [itertools.combinations(range(sbox_width), i) for i in range(1, 5)]:
            for positions in positions_len_i:
                for o_positions in o_positions_len_i:
                    approx_true = 0
                    runs = 0
                    for in_combinations in itertools.product([False, True], repeat=len(positions)):
                        for out_combinations in itertools.product([False, True], repeat=len(o_positions)):
                            input_combination = filter_list(positions, in_combinations)
                            output_combination = filter_list(
                                o_positions, out_combinations)
                            in_mask = number_from_powers(input_combination)
                            out_mask = number_from_powers(output_combination)
                            output = sbox_byte(in_mask, sbox_width) & out_mask
                            approx_true += xor_positions(output, output_combination) ^ xor_positions(
                                in_mask, input_combination)
                            runs += 1
                    correlations.append(
                        (positions, o_positions, approx_true / runs))
    return correlations


def crack(sbox_width: int = 4):
    key = npy.array(
        bytearray(b'\xB7\x62\xC1\x43\xA1\x93\x3A\x53'), dtype=npy.uint8)
    choices = find_correlations(sbox_width=4)
    filtered_choices = filter_choices(choices)
    results_even = []
    results_odd = []
    false_entries = []
    true_entries = []
    for byte in range(8):
        for positions, o_positions, correlation in filtered_choices:
            for nibble in range(0, 8, sbox_width):
                positions = list(map(lambda p: p + nibble, positions))
                o_positions = list(map(lambda p: p + nibble, o_positions))
                mask, out_mask = generate_block(
                    positions, byte), generate_block(o_positions, byte)
                ciphertext = cipher(key, mask) & out_mask
                key_bits = get_bits(key[byte])
                print('BYTE: ', byte, 'POSITIONS', positions, o_positions, 'MASK', get_bits(mask[byte]), get_bits(
                    out_mask[byte]), 'CIPHERTEXT', get_bits(ciphertext[byte]), 'KEY', key_bits, correlation)
                val = xor_positions(key[byte], positions) ^ xor_positions(
                    key[byte], o_positions)
                xoredv = xor_positions(mask[byte], positions) ^ xor_positions(
                    ciphertext[byte], o_positions)
                if correlation >= high_corr:
                    # x1 ^ x2 ^ x3 ^ y1 = 1
                    if xoredv:
                        print('pos even')
                        results_even.append((positions, o_positions))
                        if not val:
                            true_entries.append(1)
                        else:
                            false_entries.append(1)
                            print('false')
                    else:
                        print('pos odd')
                        results_odd.append((positions, o_positions))
                        if val:
                            true_entries.append(2)
                        else:
                            false_entries.append(2)
                            print('false')
                elif correlation <= low_corr:
                    # k1 ^ x1 ^ k2 ^ 1= o
                    if not xoredv:
                        print('neg even')
                        results_even.append((positions, o_positions))
                        if not val:
                            true_entries.append(3)
                        else:
                            false_entries.append(3)
                            print('false')
                    else:
                        print('neg odd')
                        results_even.append((positions, o_positions))
                        if val:
                            true_entries.append(4)
                        else:
                            false_entries.append(4)
                            print('false')

    print('TRUE', Counter(true_entries), 'FALSE', Counter(false_entries))
    print('CHOICES',
          list(filter(lambda c: c[2] <= low_corr or c[2] >= high_corr, choices)))
    print('TRUTH RATE', len(true_entries) /
          (1 + len(true_entries) + len(false_entries)))


def main():
    key = npy.array(
        bytearray(b'\xB7\x62\xF1\x43\xC1\x93\x3A\x53'), dtype=npy.uint8)
    data = npy.array(
        list(map(lambda c: ord(c), 'Hello World!')), dtype=npy.uint8)
    encrypted = cipher(key, data)
    print('ENCRYPTED', encrypted)
    decrypted = decipher(key, encrypted)
    print('DECRYPTED', decrypted)
    print('ORIGINAL', list(data))
    crack(sbox_width=4)
    print(find_correlations(sbox_width=4))


if __name__ == '__main__':
    main()
