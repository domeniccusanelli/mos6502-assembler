import sys
import re
import enum

byte_pattern = r"[a-fA-F\d]{2}"

comment_regex = re.compile(";.*")
label_regex = re.compile(r"^((?![;$#=()]).)*$")
operand_regex = re.compile(r"^(#?\$" + byte_pattern + r"|\$" + byte_pattern + byte_pattern + ")$")

# ACC_regex = re.compile()                                              # unused
IMM_regex = re.compile(r"^#\$" + byte_pattern + "$")                    # #$AA
ABS_regex = re.compile(r"^\$" + byte_pattern + byte_pattern + "$")      # $AAAA
ZPG_regex = re.compile(r"^\$" + byte_pattern + "$")                     # $AA
ZPX_regex = re.compile(r"^\$" + byte_pattern + ",[xX]$")                # $AA,X
ZPY_regex = re.compile(r"^\$" + byte_pattern + ",[yY]$")                # $AA,Y
AIX_regex = re.compile(r"^\$" + byte_pattern + byte_pattern + ",[xX]$") # $AAAA,X
AIY_regex = re.compile(r"^\$" + byte_pattern + byte_pattern + ",[yY]$") # $AAAA,Y
# IMP_regex = re.compile()                                              # unused
# REL_regex = re.compile(r"^\$" + byte_pattern + "$")                   # same as Zero Page
IIX_regex = re.compile(r"^\(\$" + byte_pattern + r",[xX]\)$")           # ($AA,X)
IIY_regex = re.compile(r"^\(\$" + byte_pattern + r"\),[yY]$")           # ($AA),Y
IND_regex = re.compile(r"^\(\$" + byte_pattern + byte_pattern + r"\)$") # ($AAAA)

mnemonic_regex = re.compile("\
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
")

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
    "BCC": Mode.REL
    "BCS": Mode.REL
    "BEQ": Mode.REL
    "BMI": Mode.REL
    "BNE": Mode.REL
    "BPL": Mode.REL
    "BRK": Mode.IMP
    "BVC": Mode.REL
    "BVS": Mode.REL
    "CLC": Mode.IMP
    "CLD": Mode.IMP
    "CLI": Mode.IMP
    "CLV": Mode.IMP
    "DEX": Mode.IMP
    "DEY": Mode.IMP
    "INX": Mode.IMP
    "INY": Mode.IMP
    "JSR": Mode.ABS
    "NOP": Mode.IMP
    "PHA": Mode.IMP
    "PHP": Mode.IMP
    "PLA": Mode.IMP
    "PLP": Mode.IMP
    "RTI": Mode.IMP
    "RTS": Mode.IMP
    "SEC": Mode.IMP
    "SED": Mode.IMP
    "SEI": Mode.IMP
    "TAX": Mode.IMP
    "TAY": Mode.IMP
    "TSX": Mode.IMP
    "TXA": Mode.IMP
    "TXS": Mode.IMP
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

'''
Collect label dictionary, and strip labels, comments, and empty lines
Invalid labels: Semicolon, opcodes, dollar sign, number sign, equals, parantheses
Allow with or without colon
LABEL AAA sets label equal to line number of AAA
LABEL = $AA or #$AA or #AAAA sets label equal to value
'''
def first_pass(lines):

    labels = {} # "label": cumulative_length + 1
    bytes_length = 0

    for num, line in enumerate(lines):

        lines[num] = re.sub(comment_regex, "", line) # remove any comments from line
        
        line_strings = line.split()
        if len(line_strings) == 0: # line was only comments or whitespace
            continue

        mnemonic = re.search(mnemonic_regex, line_strings[0])
        if mnemonic and (len(line_strings[0]) == 3): # mnemonic is first in line
            if len(line_strings) > 1:
                mnemonic_mode = get_mode(mnemonic.group(), line_strings[1])
                bytes_length += mode_length[mnemonic_mode]
            else:
                bytes_length += 1
        else: # label is first in line
            if len(line_strings) == 1:
                if "=" in line_strings[0][1:-1]: # unspaced label assignment
                    label_assignment = line_strings[0].split("=")
                    assert(re.search(operand_regex, label_assignment[1]), \
                           "Incorrect label assignment value: \
                           Labels must only be assigned addresses or immediate values.\nLine " + num)
                    labels[label_assignment[0]] = label_assignment[1]
                else: # label on empty line
                    labels[line_strings[0]] = bytes_length + 1
            elif len(line_strings) == 2:
                labels[line_strings[0]] = bytes_length + 1
                assert(re.search(mnemonic_regex, line_strings[1]), \
                       "Incorrect label placement: \
                       Labels must only be followed by an instruction or whitespace.\nLine " + num)
                bytes_length += 1
            elif len(line_strings) == 3:
                if line_strings[1] == "=":
                    assert(re.search(operand_regex, label_assignment[2]), \
                           "Incorrect label assignment value: \
                           Labels must only be assigned addresses or immediate values.\nLine " + num)
                    labels[line_strings[0]] = line_strings[2]
                else:
                    labels[line_strings[0]] = bytes_length + 1
                    assert(re.search(mnemonic_regex, line_strings[1]), \
                           "Incorrect label placement: \
                           Labels must only be followed by an instruction or whitespace.\nLine " + num)
                    mnemonic_mode = get_mode(line_strings[1], line_strings[2])
                    bytes_length += mode_length[mnemonic_mode]

    return labels

'''
Translate labels to their meanings, and commands into hex
'''
def second_pass(lines, labels): # assemble with labels

    try:
        hex_file = open(hex_filename,"w")
    except OSError as err:
        print(type(err).__name__, ": {0} \"{1}\"".format(err.strerror, sys.argv[0]))

    for num, line in enumerate(lines):
        line_strings = line.split()

        if len(line_strings) == 0: # line was only comments or whitespace
            continue

        mnemonic = re.search(mnemonic_regex, line)
        if mnemonic:
            operand = re.search(operand_regex, line)
            label = re.search(operand_regex, line)
            if operand:
                mnemonic_mode = get_mode(mnemonic.group(), operand.group())
                mnemonic_hex = mnemonic_to_hex[(mnemonic.group(), mnemonic_mode)]
            elif label:
                if label.group()[0] == '$' or label.group()[0] == '#': # if the label is an assignment label
                    mnemonic_mode = get_mode(mnemonic.group(), label.group())
                    mnemonic_hex = mnemonic_to_hex[(mnemonic.group(), mnemonic_mode)]
                else: # if the label is a subroutine label
                    # TODO calculate offset from labels[label] - bytes_length
                    # Add +1 to bytes_length if mnemonic

            else: # single mnemonic
                mnemonic_mode = get_mode(mnemonic.group(), "")
                mnemonic_hex = mnemonic_to_hex[(mnemonic.group(), mnemonic_mode)]

        hex_file.write()

def get_mode(mnemonic, operand):

    if mnemonic in static_modes:
        return static_modes[mnemonic]

    elif re.search(IMM_regex, operand):
        return Mode.IMM

    elif re.search(ABS_regex, operand):
        return Mode.ABS

    elif re.search(ZPG_regex, operand):
        return Mode.ZPG

    elif re.search(ZPX_regex, operand):
        return Mode.ZPX

    elif re.search(ZPY_regex, operand):
        return Mode.ZPY

    elif re.search(AIX_regex, operand):
        return Mode.AIX

    elif re.search(AIY_regex, operand):
        return Mode.AIY

    elif re.search(IIX_regex, operand):
        return Mode.IIX

    elif re.search(IIY_regex, operand):
        return Mode.IIY

    elif re.search(IND_regex, operand):
        return Mode.IND

    else:
        return Mode.ACC

# main

assert(sys.argv > 1, "Usage: assembler.py \"assembly file\" [\"output file\"]")

asm_filename = sys.argv[1]

if len(sys.argv) > 2:
    hex_filename = sys.argv[1]
else:
    hex_filename = asm_filename.split(".")[0]

try:
    asm_file = open(asm_filename,"r")
except OSError as err:
    print(type(err).__name__, ": {0} \"{1}\"".format(err.strerror, sys.argv[0]))

file_lines = asm_file.readlines()

label_dict = first_pass(file_lines)
second_pass(file_lines, label_dict)