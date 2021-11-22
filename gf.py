#  0b100011011 - reducing polynomial

class Gf:
    def __init__(self):
        self.log_table = [0 for _ in range(256)]
        self.antilog = [0 for _ in range(256)]
        self.g = 3
        self.__init_log_table()

    def gf_mul(self, a: int, b: int) -> int:
        """
        performs multiplication of a and b in GF(2^8)
        """
        p = 0

        for i in range(8):
            if b & 1:
                p ^= a
            a = self.x_mul(a)
            b >>= 1

        return p

    def x_mul(self, a: int) -> int:
        """performs multiplication by x(00000010) in GF(2^8)"""
        # carry_bit = a & 0x80
        # The idea is that multiplying any polynomial in GF(2^8) by x in binary
        # equals to shifting that polynomial's binary representation one bit left,
        # checking if there is a carry bit and XORing with 0x1b (truncated 0x011b), if there is one.
        # This idea can be expanded to multiply any two numbers from that finite field in binary
        sifted_l = (a << 1) & 0xFF
        return sifted_l if a & 0x80 == 0 else sifted_l ^ 0x1b

    def __init_log_table(self):
        # easier way to perform multiplication and inverting by finding log/antilog tables
        x = 1

        for i in range(256):
            self.log_table[x] = i
            self.antilog[i] = x
            x = self.gf_mul(x, self.g)

    def log_mul(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0

        x, y = self.log_table[a], self.log_table[b]
        mult = (x + y) % 255

        return self.antilog[mult]

    def log_inv(self, a: int) -> int:
        if a == 0:
            return a

        x = self.log_table[a]
        y = 255 - x

        return self.antilog[y]
