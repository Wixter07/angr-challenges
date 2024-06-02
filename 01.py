import angr

p = angr.Project('../problems/01_angr_avoid')
initial_state = p.factory.entry_state()
smgr = p.factory.simgr(initial_state)

target_address = 0x080485e5
avoid_address = 0x080485A8

smgr.explore(find=target_address, avoid=avoid_address)

if smgr.found:
    final_state = smgr.found[0]
    print(final_state.posix.dumps(0))

#HUJOZMYS