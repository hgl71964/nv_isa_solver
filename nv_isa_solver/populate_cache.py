from nv_isa_solver.disasm_utils import Disassembler, set_bit_range
from argparse import ArgumentParser


def main():
    parser = ArgumentParser()
    parser.add_argument("--arch", default="SM90a")
    parser.add_argument("--cache_file", default="disasm_cache.txt")
    parser.add_argument("--nvdisasm", default="nvdisasm")
    arguments = parser.parse_args()

    disassembler = Disassembler(arguments.arch, nvdisasm=arguments.nvdisasm)

    def flip_bit(array, i):
        bit_offset = i % 8
        array[i // 8] ^= 1 << bit_offset

    # XXX it seems to assume the first 12 bits are the opcode
    inst = []
    for i in range(pow(2, 12)):
        array = bytearray(
            b"\0" * 16)  # 16-byte buffer (128 bits instruction length, all 0)
        set_bit_range(array, 0, 12, i)  # write i into the lowest 12 bits
        inst.append(array)
        for j in range(13, 8 * 13):  # j = 13..103
            array_ = bytearray(array)
            flip_bit(array_, j)  # flip one extra bit
            inst.append(array_)

    disassembler.disassemble_parallel(inst, True)
    disassembler.dump_cache(arguments.cache_file)


if __name__ == "__main__":
    main()
