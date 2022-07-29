from memmod import Process

import sys

# Open process
proc = Process(name="tut")


# Hello World 
libsdl = proc.find_module("libSDL")
assert libsdl is not None, "Failed to locate libSDL"


#/home/daniel/Documents/Games/tut_linux/tut + 0x355f70
#/home/daniel/Documents/Games/tut_linux/tut + 0x355f78
#/home/daniel/Documents/Games/tut_linux/tut + 0x355f80

# 00000000004e4db0 <update_sdl_window_title>:
# 4e4db0:       48 8b 05 71 c9 33 00    mov    rax,QWORD PTR [rip+0x33c971]        # 821728 <sdl_window>

SDL_SetWindowTitle_addr = libsdl.start + libsdl.get_symbol_offset("SDL_SetWindowTitle")
window_ptr = int.from_bytes(proc.read(0x821728, 8), sys.byteorder)
proc.run_function(SDL_SetWindowTitle_addr, window_ptr, "Hacked the game externaly!")


puts = proc.get_libc_function("puts")
puts("Hello from memmod!")

modulebase = proc.find_module(proc.name, mode='r-xp')
assert modulebase != None, "Failed to locate modulebase"


def handle_loop(regs, _):
    return True

print(hex(modulebase.start))
proc.add_breakpoint(0x403f00, handle_loop)
proc.listen()
