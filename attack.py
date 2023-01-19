from functools import reduce
import numpy as npy
import random
import math
import itertools
from collections import Counter

sbox_maximum_width = 8 + 1
random.seed('T', version=2)
sboxes = [random.sample(range(2 ** i), k=2 ** i)
          for i in range(sbox_maximum_width)]
inv_sboxes = [[sboxes[i].index(j) for j in range(
    len(sboxes[i]))] for i in range(len(sboxes))]
powers = [2 ** x for x in range(8)]
high_corr = 0.25
print(sboxes[4], inv_sboxes[4])


def sbox_byte(b: int, sbox_size: int = 4):
    if 8 / sbox_size != int(8 / sbox_size):
        raise ValueError

    sbox_amount = int(8 / sbox_size)
    sbox = sboxes[sbox_size]
    ciphertext = 0
    for i in range(sbox_amount):
        ciphertext += sbox[b &
                           int('0b0000' + '1' * sbox_size, 2)] << i * sbox_size
        b = b >> sbox_size
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
        b = b >> sbox_size
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
    if len(input) != len(filter):
        raise ValueError
    ret = []
    for i in range(len(input)):
        if filter[i]:
            ret.append(input[i])
    return ret


def bruteforce(key: npy.array):
    for i in range(2 ** 64):
        print(i)
        if all(decipher(npy.array(i, dtype=npy.uint8), npy.array(bytearray(b'\xBF\xD3\x09\x68\60\x7C\x95\xE3'), dtype=npy.uint8), 4) == npy.array(bytearray(b'\x23\x34\x45\x56\x67\x78\x91\12'), dtype=npy.uint8)):
            return(i)


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
    return list(filter(lambda c: abs(c[2]) >= high_corr, choices))


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
            save[b] = sbox_byte(int(save[b]), sbox_size=sbox_width)
        output[i*8:(i+1)*8] = npy.bitwise_xor(save, key)
    return output


def decipher(key: npy.array, pt: npy.array, sbox_width: int = 4) -> npy.array:
    new_size = math.ceil(pt.size / 8)
    output = pt.copy()
    output.resize(new_size*8)
    for i in range(new_size):
        save = npy.bitwise_xor(output[i*8:(i+1)*8], key)
        for b in range(8):
            save[b] = inv_sbox_byte(int(save[b]), sbox_size=sbox_width)
        output[i*8:(i+1)*8] = npy.bitwise_xor(save, key)
    return output


def find_correlations(sbox_width: int = 4) -> list:
    correlations = []
    for positions_len_i in [list(itertools.combinations(range(sbox_width), i)) for i in range(2, 5)]:
        for positions in positions_len_i:
            for o_positions_len_i in [itertools.combinations(range(sbox_width), i) for i in range(1, 5)]:
                for o_positions in o_positions_len_i:
                    approx_true = 0
                    runs = 0
                    for in_combinations in itertools.product([False, True], repeat=len(positions)):
                        for out_combinations in itertools.product([False, True], repeat=len(o_positions)):
                            #print(len(list(itertools.product([False, True], repeat=len(positions)))) * len(list(itertools.product([False, True], repeat=len(o_positions)))))
                            input_combination = filter_list(
                                positions, in_combinations)
                            output_combination = filter_list(
                                o_positions, out_combinations)
                            in_mask = number_from_powers(input_combination)
                            out_mask = number_from_powers(output_combination)
                            output = sbox_byte(in_mask, sbox_size=sbox_width) & out_mask
                            approx_true += xor_positions(output, output_combination) ^ xor_positions(
                                in_mask, input_combination)
                            runs += 1
                    #print(approx_true, runs)
                    correlations.append(
                        (positions, o_positions, (approx_true / runs - 0.5) * 2))
    return correlations

def find_canceling_equations(positions: list):
    new_positions = []
    for i in range(len(positions)):
        added = positions[i][1] + positions[1][0]
        canceled_out_result = []
        for p in added:
            if p in canceled_out_result:
                canceled_out_result.remove(p)
            else:
                canceled_out_result.append(p)
        if len(canceled_out_result) < len(added) and len(canceled_out_result) >= 1:
            new_positions.append(positions[i] + (canceled_out_result,))
    return new_positions
    


def crack(sbox_width: int = 4):
    key = npy.array(
        bytearray(b'\x00\x00\x00\x00\x00\x93\x3A\x53'), dtype=npy.uint8)
    key_cpy = npy.array(
        bytearray(b'\xB7\x62\xC1\x43\xA1\x93\x3A\x53'), dtype=npy.uint8)
    choices = find_correlations(sbox_width=4)
    filtered_choices = filter_choices(choices)
    canceled_out_choices = find_canceling_equations(filtered_choices)
    results_even = []
    results_odd = []
    false_entries = []
    true_entries = []
    key_guesses = []
    result: list[int, bool] = []
    for byte in range(8):
        for positions, o_positions, correlation, bits in canceled_out_choices:
            for nibble in range(0, 8, sbox_width):
                abs_position = list(map(lambda p: byte * 8 + nibble + p, bits))
                positions = list(map(lambda p: p + nibble, positions))
                o_positions = list(map(lambda p: p + nibble, o_positions))
                mask, out_mask = generate_block(
                    positions, byte), generate_block(o_positions, byte)
                ciphertext = cipher(key, mask, sbox_width=sbox_width) & out_mask
                key_bits = get_bits(key[byte])
                print('BYTE: ', byte, 'POSITIONS', positions, o_positions, 'MASK', get_bits(mask[byte]), get_bits(
                    out_mask[byte]), 'CIPHERTEXT', get_bits(ciphertext[byte]), 'KEY', key_bits, correlation)
                val = xor_positions(key[byte], positions) ^ xor_positions(
                    key[byte], o_positions)
                xoredv = xor_positions(mask[byte], positions) ^ xor_positions(
                    ciphertext[byte], o_positions)
                if correlation <= - high_corr:
                    xoredv ^= 1
                if xoredv:
                    print('pos even')
                    results_even.append((positions, o_positions))
                    result.append([abs_position, True])
                    if not val:
                        true_entries.append(1)
                    else:
                        false_entries.append(1)
                        print('false')
                else:
                    print('pos odd')
                    results_odd.append((positions, o_positions))
                    result.append([abs_position, False])
                    if val:
                        true_entries.append(2)
                    else:
                        false_entries.append(2)
                        print('false')

    print('TRUE', Counter(true_entries), 'FALSE', Counter(false_entries))
    print('CHOICES', filter_choices(choices))
    print('TRUTH RATE', len(true_entries) /
          (1 + len(true_entries) + len(false_entries)))
    print(result)


def main():
    key = npy.array(
        bytearray(b'\xB7\x62\xF1\x43\xC1\x93\x3A\x53'), dtype=npy.uint8)
    data = npy.array(
        list(map(lambda c: ord(c), 'Hello World!')), dtype=npy.uint8)
    data2 = npy.array(bytearray(b'\x23\x34\x45\x56\x67\x78\x91\12'), dtype=npy.uint8)
    encrypted = cipher(key, data)
    encrypted2 = cipher(key, data2)
    print('ENCRYPTED', encrypted)
    print('ENCRYPTED', encrypted2)
    decrypted = decipher(key, encrypted)
    print('DECRYPTED', decrypted)
    print('ORIGINAL', list(data))
    crack(sbox_width=4)
    print(bruteforce(key))
    #print(find_correlations(sbox_width=4))
    #print(find_canceling_equations(filter_choices(find_correlations(sbox_width=4))))


if __name__ == '__main__':
    main()
