import angr

p = angr.Project('../problems/02_angr_find_condition', auto_load_libs=False)
init_state = p.factory.entry_state()
simgr = p.factory.simulation_manager(init_state)

def check_good(state):
    return b'Good Job.' in state.posix.dumps(1)

def check_bad(state):
    return b'Try again.' in state.posix.dumps(1)

simgr.explore(find=check_good, avoid=check_bad)

if simgr.found:
    final_state = simgr.found[0]
    print("Found a path")
    print(final_state.posix.dumps(0))
else:
    print("Ghey")


#HETOBRCU