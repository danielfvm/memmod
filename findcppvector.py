from memmod import Process, ScanMode
from memmod.process import ScanResult

def list_to_dict(pointers: list[ScanResult]) -> dict[int, int]:
    _pointers = {}
    for ptr in pointers:
        _pointers[ptr.address] = ptr.value
    return _pointers

proc = Process(name="supertux")

heap = proc.find_module('[heap]')
assert heap != None, "Failed to find module heap!"

results = proc.scan(ScanMode.INSIDE, heap.start, heap.end, heap.start, heap.end)
pointers = list_to_dict(results)

# a std::vector is a struct with 3 pointers next to each other
for adr, val in pointers.items():
    if val not in pointers:
        continue

    # check if below pointer is another pointer
    next_ptr = adr+0x8
    if next_ptr not in pointers:
        continue

    if pointers[next_ptr]-0x8 not in pointers:
        continue

    if adr+0x10 not in pointers:
        continue

    size = pointers[next_ptr]-val
    if size % 8 != 0 or size <= 0:
        continue

    size = int(size / 8)
    if not(size >= 200 and size <= 300):
        continue

    valid = True
    for item in range(val, pointers[next_ptr], 0x8):
        if item not in pointers:
            valid = False
            break

    if not valid:
        continue

    print(hex(adr), size)
