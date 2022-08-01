#!/bin/python3
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from memmod import Process

import enum
import argparse
import sys

class Access(enum.Enum):
    READ = 'read'
    WRITE = 'write'
    BOTH = 'both'

# Global variables
access_type: Access
addr_search: int


def handle(regs, data):
    for op_sum in data['operators']:
        for field in regs._fields_:
            value = getattr(regs, field[0])

            if field[0][0] == 'r' and field[0][-1].isdigit():
                op_sum = op_sum.replace(field[0] + 'd', str(value & 0xFFFFFFFF))
                op_sum = op_sum.replace(field[0] + 'w', str(value & 0xFFFF))
                op_sum = op_sum.replace(field[0] + 'b', str(value & 0xFF))

            op_sum = op_sum.replace(field[0], str(value))

            if field[0][0] == 'r' and len(field[0]) >= 3 and not field[0][2].isdigit():
                # replace all 32bit registers like eax, esi, ...
                op_sum = op_sum.replace('e' + field[0][1:], str(value & 0xFFFFFFFF))

                #replace all 9bit registers like ah, al, bpl
                if field[0][2] == 'x':
                    op_sum = op_sum.replace(field[0][1] + 'l', str(value & 0xFF))
                    op_sum = op_sum.replace(field[0][1] + 'h', str((value & 0xFF00) >> 8))
                else:
                    op_sum = op_sum.replace(field[0][1:] + 'l', str(value & 0xFF))

                # replace all 16bit registers like ax, bx, ...
                e_reg_name = field[0][1:]
                op_sum = op_sum.replace(e_reg_name, str(value & 0xFFFF))

        try:
            # abuse eval as an calculator, not all register might have been replaced
            # so this function could throw an error
            if eval(op_sum) == addr_search:
                print('addr: 0x%016x  access: %s  offset: %s+0x%-8x' % (regs.rip, 'write' if data['write'] else 'read', data['module'], data['offset']))
                print('asm:  %s\n' % data['asm'])
        except Exception as e:
            print(e, op_sum)
            pass

    # we don't need the breakpoint anymore so we remove it by returning False.
    return False


def insert_breakpoints_in_module(proc, name):

    # load module where we most likely will find our address
    module_base = proc.find_module(name, mode='r--p')
    module_prog = proc.find_module(name, mode='r-xp')

    if module_base == None or module_prog == None:
        print('accessanalyzer.py: error: Failed to locate module:', name)
        sys.exit()

    binary = proc.read(module_prog.start, module_prog.size)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    count = 0

    # look through the assembler code for mov instructions that could write to our address
    for instruction in md.disasm(binary, module_prog.start):
        if '[' not in instruction.op_str:
            continue
        if ',' not in instruction.op_str:
            continue
        if 'xmm' in instruction.op_str:
            continue

        progress = round((100.0/module_prog.size)*(instruction.address-module_prog.start))
        print('Inserting breakpoint in `%s` at: %016x Progress: %d/100   \r' % (module_prog.path, instruction.address, progress), end='', flush=True)

        arguments = instruction.op_str.split(',')
        write = '[' in arguments[0]
        op_write = arguments[0] if write else arguments[1]
        op_read = arguments[1] if write else arguments[0]

        if write and access_type == Access.READ:
            continue
        if not write and access_type == Access.WRITE:
            continue

        count += 1
        proc.add_breakpoint(instruction.address, handle, {
            'write': write, # if true, the asm code is writing to the address
            'operators': [op_write[op_write.find('[')+1:op_write.find(']')], op_read.strip()],
            'asm': instruction.mnemonic + ' ' + instruction.op_str,
            'offset': instruction.address-module_base.start,
            'module': module_prog.path,
        })

    # new line after \r
    print('Finished inserting breakpoints in `%s`, total breakpoints: %d' % (module_prog.path, count))


def hexvalue(x):
    return int(x, 0)


def main():
    global addr_search, access_type

    arguments = argparse.ArgumentParser()
    arguments.add_argument('-n', '--name', help='Select process by name', type=str)
    arguments.add_argument('-p', '--pid', help='Select process by pid', type=int)
    arguments.add_argument('-a', '--address', help='Scan if program has accessed following address', type=hexvalue, required=True)
    arguments.add_argument('-t', '--type', help='Set the type of access: read, write, or default: both', type=Access, default=Access.BOTH)
    arguments.add_argument('-m', '--module', help='Specify modules to scan, default: base module', type=str, default=None, nargs='+')

    args, _ = arguments.parse_known_args()
    args = vars(args)

    # we set the global variable to search for our address
    addr_search = args['address']
    access_type = args['type']

    # open process by name or it's process id
    if not args['name'] and not args['pid']:
        print('accessanalyzer.py: error: the following arguments are required: -p/--pid or -n/--name')
        sys.exit()

    proc = Process(pid=args['pid'], name=args['name'])
    print('Opend process with pid %d' % proc.pid)

    # insert breakpoints in modules
    if not args['module']:
        insert_breakpoints_in_module(proc, proc.name)
    else:
        for module in args['module']:
            insert_breakpoints_in_module(proc, module)

    print('Inserted %d breakpoints.' % len(proc._breakpoints))

    # now we start listening to our breakpoings and check them in the 'handle' function
    print('Start listening for breakpoints...\n')
    proc.listen()
    print('Deleted all breakpoints.')

if __name__ == '__main__':
    main()
