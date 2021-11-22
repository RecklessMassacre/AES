from typing import Union
from gf import Gf
from hashlib import md5


#  Each algorithm for each function is decently described in the official documentation FIPS 197
class AES:
    # TODO
    # add padding
    # implement modes and 192/256 bit variations
    # get rid of python tuples and lists and replace them with something more appropriate (like numpy arrays or smth)
    # something else
    def __init__(self, password: str):
        # Substitution table for byte shifting
        self.S_BOX = (
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        )

        # Inverse substitution table for byte shifting
        self.INV_S_BOX = (
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        )
        self.NB = 4  # number of columns in state(128-bit chunk of input data)
        self.NK = 4  # number of 32-bit keywords in cipher key
        self.NR = 10  # number of rounds

        # array of round constants. used in key expansion procedure
        self.RCON = (
            (0x00, 0x00, 0x00, 0x00),
            (0x01, 0x00, 0x00, 0x00),
            (0x02, 0x00, 0x00, 0x00),
            (0x04, 0x00, 0x00, 0x00),
            (0x08, 0x00, 0x00, 0x00),
            (0x10, 0x00, 0x00, 0x00),
            (0x20, 0x00, 0x00, 0x00),
            (0x40, 0x00, 0x00, 0x00),
            (0x80, 0x00, 0x00, 0x00),
            (0x1b, 0x00, 0x00, 0x00),
            (0x36, 0x00, 0x00, 0x00)
        )

        self.gf = Gf()  # its the module to perform some calculations in finite field GF(2^8)
        self.key = md5(password.encode()).hexdigest()
        # list of tuples, each tuple represents 32-bit word (4 unsigned 8-bit integers)
        # they are used in the encryption process
        self.w_arr = [(-1, -1, -1, -1)] * self.NB * (self.NR + 1)
        # 4x4 matrix of input data chunk, each column represents 32-bit word
        self.state = [[-1 for _ in range(4)] for _ in range(4)]
        self.key_expansion()

    def calc_single_s_box_value(self, b: int) -> int:
        """Calculates single S_BOX value."""
        # Implemented this in order to have understanding of how to build AES S_BOX myself.
        # finding multiplicative inverse in GF(2^8)
        g = self.gf.log_inv(b)
        # then performing this affine transformation
        s = g ^ self.csl(g, 1) ^ self.csl(g, 2) ^ self.csl(g, 3) ^ self.csl(g, 4) ^ 0x63

        return s

    def csl(self, h, j):
        """Circular left shift"""
        return (h << j) & 0xFF | (h >> (8 - j))

    def add_round_key(self, round_number: int):
        # key words needed for that round
        round_key = self.w_arr[round_number * self.NB: (round_number + 1) * self.NB]

        temp = [[self.state[i][j] ^ round_key[j][i] for j in range(4)] for i in range(4)]
        self.state = temp

    def inv_mix_columns(self):
        # inverse procedure for mix_columns()
        temp = [[-1 for _ in range(4)] for _ in range(4)]

        for j in range(4):
            temp[0][j] = self.gf.gf_mul(0x0e, self.state[0][j]) ^ self.gf.gf_mul(0x0b, self.state[1][j]) ^ \
                         self.gf.gf_mul(0x0d, self.state[2][j]) ^ self.gf.gf_mul(0x09, self.state[3][j])  # 0e0b0d09
            temp[1][j] = self.gf.gf_mul(0x09, self.state[0][j]) ^ self.gf.gf_mul(0x0e, self.state[1][j]) ^ \
                         self.gf.gf_mul(0x0b, self.state[2][j]) ^ self.gf.gf_mul(0x0d, self.state[3][j])  # 090e0b0d
            temp[2][j] = self.gf.gf_mul(0x0d, self.state[0][j]) ^ self.gf.gf_mul(0x09, self.state[1][j]) ^ \
                         self.gf.gf_mul(0x0e, self.state[2][j]) ^ self.gf.gf_mul(0x0b, self.state[3][j])  # 0d090e0b
            temp[3][j] = self.gf.gf_mul(0x0b, self.state[0][j]) ^ self.gf.gf_mul(0x0d, self.state[1][j]) ^ \
                         self.gf.gf_mul(0x09, self.state[2][j]) ^ self.gf.gf_mul(0x0e, self.state[3][j])  # 0b0d090e

        self.state = temp

    def inv_shift_rows(self):
        # inverse procedure for shift_rows()
        self.state = [self.state[i][-i:] + self.state[i][:4 - i] for i in range(4)]

    def inv_sub_bytes(self):
        # inverse procedure for sub_bytes()
        self.state = [[self.INV_S_BOX[self.state[i][j]] for j in range(4)] for i in range(4)]

    def mix_columns(self):
        temp = [[-1 for _ in range(4)] for _ in range(4)]

        # matrix multiplication column by column
        # (each column in temp is the product of the special matrix multiplied by the same column in state)
        # where each multiplication is GF(2^8) multiplication, and each addition is GF(2^8) addition
        for j in range(4):
            temp[0][j] = self.gf.gf_mul(0x02, self.state[0][j]) ^ self.gf.gf_mul(0x03, self.state[1][j]) ^ \
                         self.state[2][j] ^ self.state[3][j]  # 2311
            temp[1][j] = self.state[0][j] ^ self.gf.gf_mul(0x02, self.state[1][j]) ^ \
                         self.gf.gf_mul(0x03, self.state[2][j]) ^ self.state[3][j]  # 1231
            temp[2][j] = self.state[0][j] ^ self.state[1][j] ^ self.gf.gf_mul(0x02, self.state[2][j]) ^ \
                         self.gf.gf_mul(0x03, self.state[3][j])  # 1123
            temp[3][j] = self.gf.gf_mul(0x03, self.state[0][j]) ^ self.state[1][j] ^ \
                         self.state[2][j] ^ self.gf.gf_mul(0x02, self.state[3][j])  # 3112

        self.state = temp

    def rot_word(self, word: tuple) -> tuple:
        """csl for bytes in word"""
        res = (word[1], word[2], word[3], word[0])
        return res

    def shift_rows(self):
        # shifts some rows in state
        self.state = [self.state[i][i:] + self.state[i][:i - 4] for i in range(4)]

    def sub_bytes(self):
        # substitutes bytes using substitution box
        self.state = [[self.S_BOX[self.state[i][j]] for j in range(4)] for i in range(4)]

    def chunk_bytes(self, data: Union[str, bytes], chunk_size: int = 1, int_req: bool = False) -> list:
        if type(data) is bytes:
            h = data.hex()
        else:
            h = data

        if int_req:
            return [int(h[i:i + chunk_size * 2], 16) for i in range(0, len(h), chunk_size * 2)]

        return [h[i:i + chunk_size * 2] for i in range(0, len(h), chunk_size * 2)]

    def sub_word(self, word: tuple) -> tuple:
        return tuple(self.S_BOX[byte] for byte in word)

    def key_expansion(self):
        """expands the key from 4 words to 44 words"""
        key_arr = self.chunk_bytes(self.key, 1, True)

        for i in range(self.NK):
            self.w_arr[i] = (key_arr[4 * i], key_arr[4 * i + 1], key_arr[4 * i + 2], key_arr[4 * i + 3])

        for i in range(self.NK, self.NB * (self.NR + 1)):
            temp = self.w_arr[i - 1]

            if i % self.NK == 0:
                temp = self._tuple_xor(self.sub_word(self.rot_word(temp)), self.RCON[i // self.NK])
            elif (self.NK > 6) and (i % self.NK == 4):
                temp = self.sub_word(temp)

            self.w_arr[i] = self._tuple_xor(self.w_arr[i - self.NK], temp)

    def _tuple_xor(self, a: tuple, b: tuple) -> tuple:
        return tuple(ai ^ bi for ai, bi in zip(a, b))

    def chunk_to_state(self, chunk: list) -> list:
        """
        in: [8-bit int, ..., 8-bit int]
        out: matrix 4x4
        """
        return [[chunk[i + j * 4] for j in range(4)] for i in range(4)]

    def state_to_chunk(self, st: list) -> list:
        """
        in: matrix 4x4
        out: [8-bit int, ..., 8-bit int]
        """
        return [st[j][i] for i in range(4) for j in range(4)]

    def cipher(self, chunk: list) -> list:
        # actual encrypting function
        # FIPS 197 Sec. 5.1
        self.state = self.chunk_to_state(chunk)
        self.add_round_key(0)

        for i in range(1, self.NR):
            self.sub_bytes()
            self.shift_rows()
            self.mix_columns()
            self.add_round_key(i)

        self.sub_bytes()
        self.shift_rows()
        self.add_round_key(10)

        return self.state_to_chunk(self.state)

    def de_cipher(self, chunk: list) -> list:
        # actual decrypting function
        # FIPS 197 Sec. 5.3
        self.state = self.chunk_to_state(chunk)
        self.add_round_key(10)

        for i in range(self.NR - 1, 0, -1):
            self.inv_shift_rows()
            self.inv_sub_bytes()
            self.add_round_key(i)
            self.inv_mix_columns()

        self.inv_shift_rows()
        self.inv_sub_bytes()
        self.add_round_key(0)

        return self.state_to_chunk(self.state)
