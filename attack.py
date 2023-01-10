import numpy as npy
import random
import math
import itertools

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


def find_good_choices():
    powers = [2 ** x for x in range(8)]
    good_choices = []
    o_choices = set([])
    combinations = list(itertools.combinations(list(range(8)), 2))
    for combination in combinations:
        for o in range(8):
            approx_true = 0
            for pt in range(255):
                in_mask = powers[combination[0]] + powers[combination[1]]
                out_mask = powers[o]
                output = sbox[in_mask & pt]
                output &= out_mask
                if output == out_mask:
                    approx_true += 1
            
            if approx_true >= 220 or approx_true <= 30:
                good_choices.append(
                    (combination[0], combination[1], o, approx_true <= 100, approx_true))
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
    empty_block = npy.array(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00'))
    data = npy.array(list(map(lambda c: ord(c), 'Hello World!')))
    print(str(len(key)), str(len(data)))
    print(cipher(key, data))
    choices, o_choices = find_good_choices()
    print(choices)
    results_even = []
    results_odd = []
    is_right = []
    for byte in range(8):
        results_even.append([])
        results_odd.append([])
        for choice in choices:
            mask = generate_block([choice[0], choice[1]], byte)
            out_mask = generate_out_mask(7, byte)
            out = (cipher(key, mask) & out_mask)
            print(mask, out_mask, out, choice)
            if choice[3]:
                if all(out  == empty_block):
                    print('xor 1')
                    results_even[byte].append((choice[0], choice[1]))
                    key_bits = list(bin(key[byte])[2:])
                    key_bits.reverse()
                    key_bits = key_bits + list('00000000')
                    is_right.append(key_bits[choice[0]] == '1' and key_bits[choice[1]] == '1')
            else:
                if all(out  == out_mask):
                    print('x1 xor x2 = y1')
                    results_odd.append([])
                    results_odd[byte].append((choice[0], choice[1]))
                    key_bits = list(bin(key[byte])[2:])
                    key_bits.reverse()
                    key_bits = key_bits + list('00000000')
                    is_right.append(key_bits[choice[0]] == '1' and key_bits[choice[1]] == '1')
            #print(is_right[-1])
    results_even_new = []
    for i, result in enumerate(results_even_new):
        print('for byte ' + str(i) + ' the result is ' + str(result))
    
    print('is true ' + str(is_right.count(True)))
    print('is false ' + str(is_right.count(False)))
    route = ["xor", "sbox", "xor"]


if __name__ == '__main__':
    main()
