from collections import namedtuple
import json

block_size = 128
key_size = 128
word_size = block_size >> 1
mod_mask = (2 ** word_size) - 1

all_keys = []
for line in open("./round-keys"):
    all_keys.append(line.strip())


Entry = namedtuple("Entry", "c1 c2 one_count xor2")

def create_entry(ct1, ct2, one_count):
    xor2 = '{0:064b}'.format(calculate_xor2(ct1, ct2))
    return Entry(ct1, ct2, one_count, xor2)


def calculate_xor2(x, y):
    # Generate all circular shifts
    ls_1_x = ((x >> (word_size - 1)) + (x << 1)) & mod_mask
    ls_8_x = ((x >> (word_size - 8)) + (x << 8)) & mod_mask
    ls_2_x = ((x >> (word_size - 2)) + (x << 2)) & mod_mask

    # XOR Chain
    xor_1 = (ls_1_x & ls_8_x) ^ y
    xor_2 = xor_1 ^ ls_2_x

    return xor_2


def encrypt_round(x, y, k):
    """
    Complete One Feistel Round
    :param x: Upper bits of current plaintext
    :param y: Lower bits of current plaintext
    :param k: Round Key
    :return: Upper and Lower ciphertext segments
    """
    xor_2 = calculate_xor2(x, y)
    new_x = k ^ xor_2

    return new_x, x


def crack_bit(i, entries):
    ONE_COUNT_CUTOFF = 4351.5  # (128 bits * 68 rounds - 1) * (1/2)

    # if xor2[i] == 0, we would expect one_count_avg to be higher if k[i] == 1
    xor0_entries = filter(lambda e: e.xor2[i] == '0', entries)
    one_count_avg0 = (sum(map(lambda e: e.one_count, xor0_entries)) /
        len(xor0_entries))
    bit_val0 = 0 if one_count_avg0 <= ONE_COUNT_CUTOFF else 1

    # if xor2[i] == 1, we would expect one_count_avg to be lower if k[i] == 1
    xor1_entries = filter(lambda e: e.xor2[i] == '1', entries)
    one_count_avg1 = (sum(map(lambda e: e.one_count, xor1_entries)) /
        len(xor1_entries))
    bit_val1 = 1 if one_count_avg1 <= ONE_COUNT_CUTOFF else 0

    if bit_val0 != bit_val1:
        print(
            "Got different results for different x2 values. " +
            str(len(xor0_entries)) + " entries with xor2 == 0 and " +
            str(len(xor1_entries)) + " entries with xor2 == 0"
        )
    
    return str(bit_val0)


def crack_round_keys(entries):
    # mutates entries
    NUM_ROUNDS = 68
    for r in xrange(NUM_ROUNDS):
        round_key_bits = map(lambda i: crack_bit(i, entries), range(64))
        round_key = ''.join(round_key_bits)

        for i in xrange(len(entries)):
            e = entries[i]
            ct1, ct2 = encrypt_round(e.c1, e.c2, int(round_key, 2))
            entries[i] = create_entry(ct1, ct2, e.one_count)

        # print(round_key == all_keys[r], round_key, all_keys[r])
        yield round_key

def construct_master_key(round_keys):
    key = round_keys[1] + round_keys[0]
    return key


def main():
    json_entries = json.load(open("./entries.json"))
    initial_entries = []

    for json_entry in json_entries:
        pt_int = json_entry[0]
        one_count = float(json_entry[1])
        pt = '{0:0128b}'.format(pt_int)
        pt1 = int(pt[:64], 2)
        pt2 = int(pt[64:], 2)

        initial_entries.append(create_entry(pt1, pt2, one_count))

    round_keys = []
    for round_key in crack_round_keys(initial_entries):
        round_keys.append(round_key)

        # only need two keys to construct master key
        if len(round_keys) == 2:
            key = construct_master_key(round_keys)
            print(
                "Key is: \n" + key + "\n\nWait to make sure there are no "
                "discrepancies in later round keys"
            )
        # but keep iterating to make sure we have enough samples and there
        # are no discrepancies later on
            

if __name__ == "__main__":
    main()