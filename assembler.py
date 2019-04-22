import os
import sys
import re
import enum

mnemonic_pattern = "\
(ADC|\
AND|\
ASL|\
BCC|\
BCS|\
BEQ|\
BIT|\
BMI|\
BNE|\
BPL|\
BRK|\
BVC|\
BVS|\
CLC|\
CLD|\
CLI|\
CLV|\
CMP|\
CPX|\
CPY|\
DEC|\
DEX|\
DEY|\
EOR|\
INC|\
INX|\
INY|\
JMP|\
JSR|\
LDA|\
LDX|\
LDY|\
LSR|\
NOP|\
ORA|\
PHA|\
PHP|\
PLA|\
PLP|\
ROL|\
ROR|\
RTI|\
RTS|\
SBC|\
SEC|\
SED|\
SEI|\
STA|\
STX|\
STY|\
TAX|\
TAY|\
TSX|\
TXA|\
TXS|\
TYA)\
"

byte_pattern = r"[a-fA-F\d]{2}"

comment_pattern = ";.*"
label_pattern = r"((?:(?=[^\s])(?<![^\s]))((?!([;$#=()]))[^\s])+(?:(?<=[^\s])(?![^\s])))"
operand_pattern = r"(#?\${0}|\${0}({0})?(,[xXyY])?|\(\${0}((({0}|,[xX])\))|\),[yY]))".format(byte_pattern)
address_pattern = r"(#?\${0}|\${0}{0})".format(byte_pattern)

blank_line = r"^\s*$"
mnemonic_line = r"^\s*" + mnemonic_pattern + r"\s*$"
mnemonic_operand_line = r"^\s*" + mnemonic_pattern + r"\s+" + operand_pattern + r"\s*$"
mnemonic_label_line = r"^\s*" + mnemonic_pattern + r"\s+" + label_pattern + r"\s*$"
label_line = r"^\s*" + label_pattern + r"\s*$"
label_mnemonic_line = r"^\s*" + label_pattern + r"\s+" + mnemonic_pattern + r"\s*$"
label_mnemonic_operand_line = r"^\s*" + label_pattern + r"\s+" + mnemonic_pattern + r"\s+" + operand_pattern + r"\s*$"
label_mnemonic_label_line = r"^\s*" + label_pattern + r"\s+" + mnemonic_pattern + r"\s+" + label_pattern + r"\s*$"
label_assignment_line = r"^\s*" + label_pattern + r"\s*" + "=" + r"\s*" + address_pattern + r"\s*$"

# ACC_pattern                                              # unused
IMM_pattern = r"^#\${0}$".format(byte_pattern)             # #$AA
ABS_pattern = r"^\${0}{0}$".format(byte_pattern)           # $AAAA
ZPG_pattern = r"^\${0}$".format(byte_pattern)              # $AA
ZPX_pattern = r"^\${0},[xX]$".format(byte_pattern)         # $AA,X
ZPY_pattern = r"^\${0},[yY]$".format(byte_pattern)         # $AA,Y
AIX_pattern = r"^\${0}{0},[xX]$".format(byte_pattern)      # $AAAA,X
AIY_pattern = r"^\${0}{0},[yY]$".format(byte_pattern)      # $AAAA,Y
# IMP_pattern                                              # unused
# REL_pattern                                              # same as Zero Page
IIX_pattern = r"^\(\${0},[xX]\)$".format(byte_pattern)     # ($AA,X)
IIY_pattern = r"^\(\${0}\),[yY]$".format(byte_pattern)     # ($AA),Y
IND_pattern = r"^\(\${0}{0}\)$".format(byte_pattern)       # ($AAAA)

class Mode(enum.Enum):
    ACC = 1
    IMM = 2
    ABS = 3
    ZPG = 4
    ZPX = 5
    ZPY = 6
    AIX = 7
    AIY = 8
    IMP = 9
    REL = 10
    IIX = 11
    IIY = 12
    IND = 13

mode_length = {
    Mode.ACC: 1,
    Mode.IMM: 2,
    Mode.ABS: 3,
    Mode.ZPG: 2,
    Mode.ZPX: 2,
    Mode.ZPY: 2,
    Mode.AIX: 3,
    Mode.AIY: 3,
    Mode.IMP: 1,
    Mode.REL: 2,
    Mode.IIX: 2,
    Mode.IIY: 2,
    Mode.IND: 3
}

static_modes = {
    "BCC": Mode.REL,
    "BCS": Mode.REL,
    "BEQ": Mode.REL,
    "BMI": Mode.REL,
    "BNE": Mode.REL,
    "BPL": Mode.REL,
    "BRK": Mode.IMP,
    "BVC": Mode.REL,
    "BVS": Mode.REL,
    "CLC": Mode.IMP,
    "CLD": Mode.IMP,
    "CLI": Mode.IMP,
    "CLV": Mode.IMP,
    "DEX": Mode.IMP,
    "DEY": Mode.IMP,
    "INX": Mode.IMP,
    "INY": Mode.IMP,
    "JSR": Mode.ABS,
    "NOP": Mode.IMP,
    "PHA": Mode.IMP,
    "PHP": Mode.IMP,
    "PLA": Mode.IMP,
    "PLP": Mode.IMP,
    "RTI": Mode.IMP,
    "RTS": Mode.IMP,
    "SEC": Mode.IMP,
    "SED": Mode.IMP,
    "SEI": Mode.IMP,
    "TAX": Mode.IMP,
    "TAY": Mode.IMP,
    "TSX": Mode.IMP,
    "TXA": Mode.IMP,
    "TXS": Mode.IMP,
    "TYA": Mode.IMP
}

mnemonic_to_hex = {
    ("BRK", Mode.IMP): 0x00,
    ("ORA", Mode.IIX): 0x01,
    ("ORA", Mode.ZPG): 0x05,
    ("ASL", Mode.ZPG): 0x06,
    ("PHP", Mode.IMP): 0x08,
    ("ORA", Mode.IMM): 0x09,
    ("ASL", Mode.ACC): 0x0A,
    ("ORA", Mode.ABS): 0x0D,
    ("ASL", Mode.ABS): 0x0E,
    ("BPL", Mode.REL): 0x10,
    ("ORA", Mode.IIY): 0x11,
    ("ORA", Mode.ZPX): 0x15,
    ("ASL", Mode.ZPX): 0x16,
    ("CLC", Mode.IMP): 0x18,
    ("ORA", Mode.AIY): 0x19,
    ("ORA", Mode.AIX): 0x1D,
    ("ASL", Mode.AIX): 0x1E,
    ("JSR", Mode.ABS): 0x20,
    ("AND", Mode.IIX): 0x21,
    ("BIT", Mode.ZPG): 0x24,
    ("AND", Mode.ZPG): 0x25,
    ("ROL", Mode.ZPG): 0x26,
    ("PLP", Mode.IMP): 0x28,
    ("AND", Mode.IMM): 0x29,
    ("ROL", Mode.ACC): 0x2A,
    ("BIT", Mode.ABS): 0x2C,
    ("AND", Mode.ABS): 0x2D,
    ("ROL", Mode.ABS): 0x2E,
    ("BMI", Mode.REL): 0x30,
    ("AND", Mode.IIY): 0x31,
    ("AND", Mode.ZPX): 0x35,
    ("ROL", Mode.ZPX): 0x36,
    ("SEC", Mode.IMP): 0x38,
    ("AND", Mode.AIY): 0x39,
    ("AND", Mode.AIX): 0x3D,
    ("ROL", Mode.AIX): 0x3E,
    ("RTI", Mode.IMP): 0x40,
    ("EOR", Mode.IIX): 0x41,
    ("EOR", Mode.ZPG): 0x45,
    ("LSR", Mode.ZPG): 0x46,
    ("PHA", Mode.IMP): 0x48,
    ("EOR", Mode.IMM): 0x49,
    ("LSR", Mode.ACC): 0x4A,
    ("JMP", Mode.ABS): 0x4C,
    ("EOR", Mode.ABS): 0x4D,
    ("LSR", Mode.ABS): 0x4E,
    ("BVC", Mode.REL): 0x50,
    ("EOR", Mode.IIY): 0x51,
    ("EOR", Mode.ZPX): 0x55,
    ("LSR", Mode.ZPX): 0x56,
    ("CLI", Mode.IMP): 0x58,
    ("EOR", Mode.AIY): 0x59,
    ("EOR", Mode.AIX): 0x5D,
    ("LSR", Mode.AIX): 0x5E,
    ("RTS", Mode.IMP): 0x60,
    ("ADC", Mode.IIX): 0x61,
    ("ADC", Mode.ZPG): 0x65,
    ("ROR", Mode.ZPG): 0x66,
    ("PLA", Mode.IMP): 0x68,
    ("ADC", Mode.IMM): 0x69,
    ("ROR", Mode.ACC): 0x6A,
    ("JMP", Mode.IND): 0x6C,
    ("ADC", Mode.ABS): 0x6D,
    ("ROR", Mode.ABS): 0x6E,
    ("BVS", Mode.REL): 0x70,
    ("ADC", Mode.IIY): 0x71,
    ("ADC", Mode.ZPX): 0x75,
    ("ROR", Mode.ZPX): 0x76,
    ("SEI", Mode.IMP): 0x78,
    ("ADC", Mode.AIY): 0x79,
    ("ADC", Mode.AIX): 0x7D,
    ("ROR", Mode.AIX): 0x7E,
    ("STA", Mode.IIX): 0x81,
    ("STY", Mode.ZPG): 0x84,
    ("STA", Mode.ZPG): 0x85,
    ("STX", Mode.ZPG): 0x86,
    ("DEY", Mode.IMP): 0x88,
    ("TXA", Mode.IMP): 0x8A,
    ("STY", Mode.ABS): 0x8C,
    ("STA", Mode.ABS): 0x8D,
    ("STX", Mode.ABS): 0x8E,
    ("BCC", Mode.REL): 0x90,
    ("STA", Mode.IIY): 0x91,
    ("STY", Mode.ZPX): 0x94,
    ("STA", Mode.ZPX): 0x95,
    ("STX", Mode.ZPY): 0x96,
    ("TYA", Mode.IMP): 0x98,
    ("STA", Mode.AIY): 0x99,
    ("TXS", Mode.IMP): 0x9A,
    ("STA", Mode.AIX): 0x9D,
    ("LDY", Mode.IMM): 0xA0,
    ("LDA", Mode.IIX): 0xA1,
    ("LDX", Mode.IMM): 0xA2,
    ("LDY", Mode.ZPG): 0xA4,
    ("LDA", Mode.ZPG): 0xA5,
    ("LDX", Mode.ZPG): 0xA6,
    ("TAY", Mode.IMP): 0xA8,
    ("LDA", Mode.IMM): 0xA9,
    ("TAX", Mode.IMP): 0xAA,
    ("LDY", Mode.ABS): 0xAC,
    ("LDA", Mode.ABS): 0xAD,
    ("LDX", Mode.ABS): 0xAE,
    ("BCS", Mode.REL): 0xB0,
    ("LDA", Mode.IIY): 0xB1,
    ("LDY", Mode.ZPX): 0xB4,
    ("LDA", Mode.ZPX): 0xB5,
    ("LDX", Mode.ZPY): 0xB6,
    ("CLV", Mode.IMP): 0xB8,
    ("LDA", Mode.AIY): 0xB9,
    ("TSX", Mode.IMP): 0xBA,
    ("LDY", Mode.AIX): 0xBC,
    ("LDA", Mode.AIX): 0xBD,
    ("LDX", Mode.AIY): 0xBE,
    ("CPY", Mode.IMM): 0xC0,
    ("CMP", Mode.IIX): 0xC1,
    ("CPY", Mode.ZPG): 0xC4,
    ("CMP", Mode.ZPG): 0xC5,
    ("DEC", Mode.ZPG): 0xC6,
    ("INY", Mode.IMP): 0xC8,
    ("CMP", Mode.IMM): 0xC9,
    ("DEX", Mode.IMP): 0xCA,
    ("CPY", Mode.ABS): 0xCC,
    ("CMP", Mode.ABS): 0xCD,
    ("DEC", Mode.ABS): 0xCE,
    ("BNE", Mode.REL): 0xD0,
    ("CMP", Mode.IIY): 0xD1,
    ("CMP", Mode.ZPX): 0xD5,
    ("DEC", Mode.ZPX): 0xD6,
    ("CLD", Mode.IMP): 0xD8,
    ("CMP", Mode.AIY): 0xD9,
    ("CMP", Mode.AIX): 0xDD,
    ("DEC", Mode.AIX): 0xDE,
    ("CPX", Mode.IMM): 0xE0,
    ("SBC", Mode.IIX): 0xE1,
    ("CPX", Mode.ZPG): 0xE4,
    ("SBC", Mode.ZPG): 0xE5,
    ("INC", Mode.ZPG): 0xE6,
    ("INX", Mode.IMP): 0xE8,
    ("SBC", Mode.IMM): 0xE9,
    ("NOP", Mode.IMP): 0xEA,
    ("CPX", Mode.ABS): 0xEC,
    ("SBC", Mode.ABS): 0xED,
    ("INC", Mode.ABS): 0xEE,
    ("BEQ", Mode.REL): 0xF0,
    ("SBC", Mode.IIY): 0xF1,
    ("SBC", Mode.ZPX): 0xF5,
    ("INC", Mode.ZPX): 0xF6,
    ("SED", Mode.IMP): 0xF8,
    ("SBC", Mode.AIY): 0xF9,
    ("SBC", Mode.AIX): 0xFD,
    ("INC", Mode.AIX): 0xFE
}

def get_assignment_labels(filename):
    labels = {}

    with open(filename, "r") as file:
        for line in file:

            line = re.sub(comment_pattern, "", line) # remove any comments from line
                
            if re.search(label_assignment_line, line):
                label = re.search(label_pattern, line).group()
                address = re.search(address_pattern, line).group()
                if label in labels:
                    print(line.split(), ": Multiple label assignments may cause undefined behavior.")
                labels[label] = address
            else:
                continue

    return labels

def first_pass(filename):
    labels = get_assignment_labels(filename)
    bytes_length = 0

    with open(filename, "r") as file:
        for line in file:

            line = re.sub(comment_pattern, "", line) # remove any comments from line
            
            if re.search(blank_line, line):
                continue

            elif re.search(mnemonic_line, line):
                bytes_length += 1

            elif re.search(mnemonic_operand_line, line):
                mnemonic = re.search(mnemonic_pattern, line).group()
                operand_string = re.search(operand_pattern, line).group()
                mode = get_mode(mnemonic, operand_string)
                bytes_length += mode_length[mode]

            elif re.search(mnemonic_label_line, line):
                operand_label = re.findall(label_pattern, line)[-1]

                mnemonic = re.search(mnemonic_pattern, line).group()
                if mnemonic in static_modes:
                    mode = static_modes[mnemonic]
                    bytes_length += mode_length[mode]
                else:
                    operand_string = labels[operand_label]
                    mode = get_mode(mnemonic, operand_string)
                    bytes_length += mode_length[mode]

            elif re.search(label_line, line):
                label = re.search(label_pattern, line).group()
                labels[label] = bytes_length

            elif re.search(label_mnemonic_line, line):
                label = re.search(label_pattern, line).group()
                labels[label] = bytes_length

                bytes_length += 1

            elif re.search(label_mnemonic_operand_line, line):
                label = re.search(label_pattern, line).group()
                labels[label] = bytes_length

                mnemonic = re.search(mnemonic_pattern, line).group()
                operand_string = re.search(operand_pattern, line).group()
                mode = get_mode(mnemonic, operand_string)
                bytes_length += mode_length[mode]

            elif re.search(label_mnemonic_label_line, line):
                line_labels = re.findall(label_pattern, line)
                label = line_labels[0]
                operand_label = line_labels[-1]
                labels[label] = bytes_length

                mnemonic = re.search(mnemonic_pattern, line).group()
                if mnemonic in static_modes:
                    mode = static_modes[mnemonic]
                    bytes_length += mode_length[mode]
                else:
                    operand_string = labels[operand_label]
                    mode = get_mode(mnemonic, operand_string)
                    bytes_length += mode_length[mode]

    return labels

def second_pass(in_filename, out_filename, labels):
    bytes_length = 0

    try:
        os.remove(out_filename)
    except OSError:
        pass

    with open(out_filename, "wb") as out_file:
        with open(in_filename, "r") as in_file:
            for line in in_file:

                line = re.sub(comment_pattern, "", line) # remove any comments from line
                
                if re.search(blank_line, line):
                    continue

                elif re.search(label_line, line):
                    continue

                elif re.search(label_assignment_line, line):
                    continue

                elif re.search(mnemonic_line, line) or re.search(label_mnemonic_line, line):
                    mnemonic = re.search(mnemonic_pattern, line).group()

                    mode = get_mode(mnemonic, "")
                    instr_length = mode_length[mode]
                    bytes_length += instr_length
                    
                    mnemonic_byte = mnemonic_to_hex[(mnemonic, mode)]
                    out_file.write(bytes([mnemonic_byte]))

                elif re.search(mnemonic_operand_line, line) or re.search(label_mnemonic_operand_line, line):
                    mnemonic = re.search(mnemonic_pattern, line).group()
                    operand_string = re.search(operand_pattern, line).group()

                    mode = get_mode(mnemonic, operand_string)
                    operand = convert_operand(operand_string, mode)
                    instr_length = mode_length[mode]
                    bytes_length += instr_length
                    
                    mnemonic_byte = mnemonic_to_hex[(mnemonic, mode)]
                    out_file.write(bytes([mnemonic_byte]))

                    if instr_length == 3:
                        high_byte = int(operand[:2], 16)
                        low_byte = int(operand[2:], 16)
                        out_file.write(bytes([low_byte]))
                        out_file.write(bytes([high_byte]))

                    else:
                        operand_byte = int(operand, 16)
                        out_file.write(bytes([operand_byte]))

                elif re.search(mnemonic_label_line, line) or re.search(label_mnemonic_label_line, line):
                    mnemonic = re.search(mnemonic_pattern, line).group()
                    label = re.findall(label_pattern, line)[-1]
                    operand_string = labels[label]

                    if type(operand_string) == str:
                        mode = get_mode(mnemonic, operand_string)
                        operand = convert_operand(operand_string, mode)
                        instr_length = mode_length[mode]
                        bytes_length += instr_length
                        
                        mnemonic_byte = mnemonic_to_hex[(mnemonic, mode)]
                        out_file.write(bytes([mnemonic_byte]))

                        if instr_length == 3:
                            high_byte = int(operand[:2], 16)
                            low_byte = int(operand[2:], 16)
                            out_file.write(bytes([low_byte]))
                            out_file.write(bytes([high_byte]))

                        else:
                            operand_byte = int(operand, 16)
                            out_file.write(bytes([operand_byte]))

                    else:
                        mode = Mode.REL
                        instr_length = mode_length[mode]
                        bytes_length += instr_length
                        offset = label - bytes_length
                        assert (offset >= -128 and offset <= 127), str(line.split()) + ": Label offset out of range [-128, 127]."
                        
                        try:
                            mnemonic_byte = mnemonic_to_hex[(mnemonic, mode)]
                            out_file.write(bytes([mnemonic_byte]))
                        except KeyError:
                            print(line.split(), ": Non-assignment labels as operands are only supported for Relative branching.")

                        if offset < 0:
                            offset = 256 + offset

                        out_file.write(bytes([offset]))

def get_mode(mnemonic, operand):

    if mnemonic in static_modes:
        return static_modes[mnemonic]

    elif re.search(IMM_pattern, operand):
        return Mode.IMM

    elif re.search(ABS_pattern, operand):
        return Mode.ABS

    elif re.search(ZPG_pattern, operand):
        return Mode.ZPG

    elif re.search(ZPX_pattern, operand):
        return Mode.ZPX

    elif re.search(ZPY_pattern, operand):
        return Mode.ZPY

    elif re.search(AIX_pattern, operand):
        return Mode.AIX

    elif re.search(AIY_pattern, operand):
        return Mode.AIY

    elif re.search(IIX_pattern, operand):
        return Mode.IIX

    elif re.search(IIY_pattern, operand):
        return Mode.IIY

    elif re.search(IND_pattern, operand):
        return Mode.IND

    else:
        return Mode.ACC

def convert_operand(operand, mode):

    if mode == Mode.IMM:
        hex_string = re.search(byte_pattern, operand).group()
        return hex_string

    elif mode == Mode.ABS:
        hex_string = re.search(byte_pattern + byte_pattern, operand).group()
        return hex_string

    elif mode == Mode.ZPG:
        hex_string = re.search(byte_pattern, operand).group()
        return hex_string 

    elif mode == Mode.ZPX:
        hex_string = re.search(byte_pattern, operand).group()
        return hex_string 

    elif mode == Mode.ZPY:
        hex_string = re.search(byte_pattern, operand).group()
        return hex_string 

    elif mode == Mode.AIX:
        hex_string = re.search(byte_pattern + byte_pattern, operand).group()
        return hex_string 

    elif mode == Mode.AIY:
        hex_string = re.search(byte_pattern + byte_pattern, operand).group()
        return hex_string 

    elif mode == Mode.REL:
        hex_string = re.search(byte_pattern, operand).group()
        return hex_string 

    elif mode == Mode.IIX:
        hex_string = re.search(byte_pattern, operand).group()
        return hex_string 

    elif mode == Mode.IIY:
        hex_string = re.search(byte_pattern, operand).group()
        return hex_string 

    elif mode == Mode.IND:
        hex_string = re.search(byte_pattern + byte_pattern, operand).group()
        return hex_string 

#assert len(sys.argv) > 1, "Usage: assembler.py \"assembly file\" [\"output file\"]"

'''
asm_filename = sys.argv[1]

if len(sys.argv) > 2:
    hex_filename = sys.argv[2].split(".")[0]
else:
    hex_filename = asm_filename.split(".")[0]

hex_filename += ".hex"
'''
asm_filename = "test.asm"
hex_filename = "test.hex"

label_dict = first_pass(asm_filename)
second_pass(asm_filename, hex_filename, label_dict)
