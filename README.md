# memmod
A library to modify another program's memory on linux x64. The goal of this library is to provide easy
functions to modify the memory of another application externaly. Additionaly creating a program like
[CheatEngine](https://cheatengine.org/) that runs natively on Linux with many features that CheatEngine provides.


## Features
* read/write to a process
* inject breakpoints and listen to them
* execute functions within the target process
* find modules from `/proc/pid/maps` by name, mode, offset or address
* inject `.so` into target process with `load_shaderd_library`
* create function detours with an optional trampoline
* bindings for ptrace
* get path to binary file with `get_path_to_executable`
* search pattern in a module with a signature
* resolve a pointerchain to find addresses, can be used with the [Pointer Scanner](scripts/pointerscanner.py).
* supports mono specific calls, [see here](memmod/monomanager.py)
* find symbol and relocation offsets within a module


## How it works
### Finding processes and reading/writing to them
We use the `/proc/` folder that "stores" all processes in separate folders with their Process-ID (pid) as the folder name.
Each process has a `/proc/pid/status` file that contains the process name, a `/proc/pid/maps` file with all the memory regions
listed, a `/proc/pid/mem` "file" in which we can read/write in to the memory of the process (with the necessary permissions).
For reading and writting use the functions `read()` and `write()`, searching for a module can be done by using the functions
`find_module()` and `find_module_with_address()`.

### Debugging
For debugging we use the ptrace systemcall that allows us to stop a process, read its registers and continue until it reaches
a breakpoint. A breakpoint in x64 linux is the hex number 0xCC and we can simply write this byte into the process as explained
in the previous section. To use the debugger with this library run `with proc.ptrace() as ptrace:`, when running this, it will
automatically attach to the process and stops, after that it will NOT detach, but instead just continue! If you want it to detach
you will need todo it manually with `ptrace.detach()`.
For easier handling with debugging and breakpoints you can use `add_breakpoint()`, it will take an `address` and a `handler` that
is being executed as soon as the target process reaches the breakpoint. Optionaly you can provide it with data that can be used
int the handler. The handler will receive the registers and the data if provided. The handler must return a boolean, if it returns
`False` the breakpoint will be removed, to keep the breakpoint return `True`. But to start listening to the breakpoints you will
need to run the `listen()` function. Note that the breakpoints are not being written into the memory by `add_breakpoint()` but by
`listen()`. Listen will stop when all breakpoints have been deleted or the user interrupts it with ctrl+c, which will lead to the
automatic removal of all breakpoints. Look [here](/examples/) for examples on how to use it.

### Function execution
We use ptrace to stop the application and write the `call rax` instruction at the current `rip` location and a breakpoint after 
that. We load into the `rax` register the address to the function we want to execute and the other register are being set to the 
arguments we want to pass to the function. After setting the registers, we continue the process flow and will reset the registers 
and the overwritten binary as soon as we reach the breakpoint. To use this feature use the function `run_function()`.
For more information see [this](https://ancat.github.io/python/2019/01/01/python-ptrace.html) article.



## Scripts
To show the capabilities of this library I programmed a few scripts that can be helpful when searching
for addresses. These scripts where inspired by the functionalities of [CheatEngine](https://cheatengine.org/).
* [Access Analyzer](scripts/accessanalyzer.py)
* [Pointer Scanner](scripts/pointerscanner.py)


## Resources
Here are some useful links to websites that helped me making this library and the scripts.
* [GUided Hacking - Read / Write to memory](https://www.youtube.com/watch?v=VMlW7BoI_IQ)
* [Linux-Inject](https://github.com/gaffe23/linux-inject)
* [ELF-Structure](https://uclibc.org/docs/elf-64-gen.pdf)
* [Injecting Code with Ptrace](https://ancat.github.io/python/2019/01/01/python-ptrace.html)
* [BananaBot - CSGO hacking](https://bananamafia.dev/post/bananabot/)
* [C++ vtables](https://defuse.ca/exploiting-cpp-vtables.htm)
* [LD_PRELOAD and Symbols](http://www.goldsborough.me/c/low-level/kernel/2016/08/29/16-48-53-the_-ld_preload-_trick/)
* [Guided Hacking - Function hooking](https://guidedhacking.com/threads/how-to-hook-functions-code-detouring-guide.14185/)
* [Guided Hacking - Unity / Mono](https://www.youtube.com/watch?v=e7cCus-LfBo)


## Tools
Some tools and programs that I used when testing and debugging the library and it's scripts.
* readelf (read symbols from binary file)
* objdump (assembler code of binary file)
* gdb (for debugging the target process)
