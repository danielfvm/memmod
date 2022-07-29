from memmod import MonoProcess

proc = MonoProcess(name="SwallowTheSea")
print("Connected:", proc.pid, proc.image)

playerController = proc.get_mono_class("PlayerController")
damage_addr = playerController.get_method_addr("Damage")
stamina_offset = playerController.get_field_offset("_staminaCoolDownTime")

print("class:", playerController)
print("damage_addr:", hex(damage_addr))
print("stamina_offset:", hex(stamina_offset))

objbase_addr = 0
def handle_damage(regs, _):
    global objbase_addr

    print("Got damage, rdi:", regs.rdi)
    objbase_addr = regs.rdi

    return False

proc.write(damage_addr, 0xC3) # insert ret to prevent getting damage
proc.add_breakpoint(damage_addr, handle_damage)
proc.listen()

stamina_addr = objbase_addr + stamina_offset
print("stamina_addr:", hex(stamina_addr))

proc.write(stamina_addr, 0, 8)
