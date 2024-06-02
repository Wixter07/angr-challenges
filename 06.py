import angr
import sys 

def found_path(state):
    return b'Good Job.' in state.posix.dumps(1)

def abort_path(state):
    return b'L.' in state.posix.dumps(1)

def execute():
    p = angr.Project('../problems/06_angr_symbolic_dynamic_memory')
    blank_state = p.factory.blank_state(addr=0x08048696)

    heap_addr = 0x602000
    buf0 = 0x0ABCC8A4
    buf1 = 0x0ABCC8AC
    sym_pw1 = blank_state.solver.BVS('sym_pw1', 8*8)
    sym_pw2 = blank_state.solver.BVS('sym_pw2', 8*8)

    blank_state.mem[buf0].uint32_t = heap_addr
    blank_state.mem[buf1].uint32_t = heap_addr + 9

    blank_state.memory.store(heap_addr, sym_pw1)
    blank_state.memory.store(heap_addr + 9, sym_pw2)

    smgr = p.factory.simgr(blank_state)
    smgr.explore(find=found_path, avoid=abort_path)

    if smgr.found:
        final_state = smgr.found[0]
        flag = final_state.solver.eval(sym_pw1, cast_to=bytes) + final_state.solver.eval(sym_pw2, cast_to=bytes)
        print('flag:', flag)
    else:
        raise Exception('No solution')

if __name__ == '__main__':
    execute()

#UBDKLMBVUNOERNYS