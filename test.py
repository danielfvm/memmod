from memmod import Process, Module

process = Process(name="test")
base = process.find_module(process.name)
print(hex(base.start+base.get_symbol_offset("a")))
