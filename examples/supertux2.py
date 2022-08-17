from memmod import Process

proc = Process(name="supertux2")

# Find base module
modulebase = proc.find_module(proc.name)
assert modulebase != None, "Failed to find module base"

def handle(regs, _):
    print("bonus value:", regs.rax)

    regs.rax = 2 # our cheat
    return True

print("breakpoint:", hex(modulebase.start + 0x311566))
proc.add_breakpoint(modulebase.start + 0x311566, handle)
proc.listen()
