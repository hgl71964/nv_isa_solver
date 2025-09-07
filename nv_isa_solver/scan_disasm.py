"""
Scan a dissassembly file to add to the corpus.

`cuobjdump --dump-sass --gpu-architecture sm_90 file`

dump a library so for analysis:
`cuobjdump -sass -arch sm_100a /usr/local/cuda/lib64/libcublas.so
"""

from nv_isa_solver.parser import InstructionParser
from nv_isa_solver.disasm_utils import Disassembler, get_bit_range

import argparse
from argparse import ArgumentParser
from tqdm import tqdm


def to_bytes(first, second):
    first = first.strip()
    second = second.strip()

    def reverse_(a):
        return "".join(reversed([a[i : i + 2] for i in range(0, len(a), 2)]))

    return bytes.fromhex(reverse_(first[2:]) + reverse_(second[2:]))

def main():
    arg_parser = ArgumentParser()
    arg_parser.add_argument("--arch", default="SM90a")
    arg_parser.add_argument("--cache_file", default="disasm_cache.txt")
    arg_parser.add_argument("--nvdisasm", default="nvdisasm")
    arg_parser.add_argument("file", type=argparse.FileType("r"))
    arg_parser.add_argument("--max", default=10000, help='max line to process')

    arguments = arg_parser.parse_args()

    disassembler = Disassembler(arguments.arch, nvdisasm=arguments.nvdisasm)
    disassembler.load_cache(arguments.cache_file)
    print(f'Cache size: {len(disassembler.cache)}')

    instructions = disassembler.find_uniques_from_cache()
    uncached = set()

    def process_instruction(disasm, instbytes):
        nonlocal instructions, uncached

        # rely on the parser to recognize SASS semantics
        try:
            parsed = InstructionParser.parseInstruction(disasm)
        except Exception:
            print("Couldn't parse", inst)
            return False

        # XXX assume first 12 bits are opcode?
        opcode = get_bit_range(instbytes, 0, 12)  
        key = f"{opcode}.{parsed.get_key()}"
        if key not in instructions:
            instructions[key] = instbytes
            uncached.add(key)
            return True
        return False

    # parse cuobjdump output
    # format: 

	#code for sm_100a
	#.target	sm_100a

	#	Function : add_kernel
	#.headerflags	@"EF_CUDA_SM100 EF_CUDA_VIRTUAL_SM(EF_CUDA_SM100)"
    #    /*0000*/                   LDC R1, c[0x0][0x37c] ;                       /* 0x0000df00ff017b82 */
    #                                                                             /* 0x000e220000000800 */
    #    /*0010*/                   S2R R0, SR_TID.X ;                            /* 0x0000000000007919 */
    #                                                                             /* 0x000e620000002100 */
    #    /*0020*/                   LDCU UR6, c[0x0][0x398] ;                     /* 0x00007300ff0677ac */
    #                                                                             /* 0x000eac0008000800 */
    #    ...

    prev_line_dump = None
    asm = None

    # for i, line in tqdm(enumerate(arguments.file)):
    progress_bar = tqdm(enumerate(arguments.file), 
                        desc="Processing SASS", 
                        unit=" lines")
    for i, line in progress_bar:
        line = line.strip()

        # skip until sass instructions
        if not line.startswith("/*"):
            continue

        new_asm = None
        if line.count("/*") == 2:
            line_rest = line[line.find("*/") + 2 :].strip()
            new_asm = line_rest[: line_rest.find("/*")].strip()[:-1]
        else:
            line_rest = line

        line_dump = line_rest[line_rest.find("/*") + 2 : line_rest.find("*/")]
        if new_asm is not None:
            prev_line_dump = line_dump
            asm = new_asm
            continue

        inst = to_bytes(prev_line_dump, line_dump)
        if process_instruction(asm, inst):
            distilled_inst = disassembler.distill_instruction(inst)  # will add to cache
            # print("Distilling: ", asm, "->", distilled_inst)
            tqdm.write(f"Distilling: {asm} -> {distilled_inst}")
        
        if i > int(arguments.max):
            # print(f"Reached max line {arguments.max}, stopping")
            tqdm.write(f"Reached max line {arguments.max}, stopping.")
            break

    print("Found", len(uncached), "instructions")
    print(f'Cache size: {len(disassembler.cache)}')
    disassembler.dump_cache(arguments.cache_file)


if __name__ == "__main__":
    main()
