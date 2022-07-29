from memmod import Process


# Open process
proc = Process(name="supertux2")


# Hello World 
puts = proc.get_libc_function("puts")
puts("Hello World")



# Find base module
modulebase = proc.find_module(proc.name)
assert modulebase is not None, "Failed to find module base"



# Pointer chain 
static_ptr = modulebase.start + 0x6CBC40
coin_ptr_addr = proc.resolve_pointer_chain(static_ptr, [0x28, 0x20, 0x0])
proc.write(coin_ptr_addr, 1000)
print("Coin addr:", hex(coin_ptr_addr))



# Breakpoint example
def handle(regs, _):
    print("bonus value:", regs.rax)
    puts("bonus value " + str(regs.rax))

    regs.rax = 2 # our cheat

    return True

proc.add_breakpoint(modulebase.start + 0x311566, handle)
proc.listen()
