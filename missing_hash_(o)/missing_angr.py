import angr

p = angr.Project('crackme2_fix4.exe', load_options={"auto_load_libs": False})
state = p.factory.entry_state(addr=0x004015B6)
start_addr = 0x040305A

input_addr = state.se.BVS("str", 8 * 10)
state.memory.store(start_addr, input_addr)

path = p.factory.path(state=state)
ex = p.surveyors.Explorer(start=path, find=0x401B21, avoid=0x00401B1)
ex.run()

print '[+] ',ex._f.state.se.any_str(input_addr)
