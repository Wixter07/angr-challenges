import angr
import claripy
import sys

def found_path(state):
    return b'Good Job.' in state.posix.dumps(1)

def abort_path(state):
    return b'Try again.' in state.posix.dumps(1)

def execute():
    p = angr.Project('../problems/04_angr_symbolic_stack')
    start_addr = 0x08048697
    blank_state = p.factory.blank_state(addr=start_addr)

    blank_state.regs.ebp = blank_state.regs.esp
    bv1 = blank_state.solver.BVS('bv1', 32)
    bv2 = blank_state.solver.BVS('bv2', 32)

    padding_len = 0x8
    blank_state.regs.esp -= padding_len

    blank_state.stack_push(bv1)
    blank_state.stack_push(bv2)

    smgr = p.factory.simgr(blank_state)
    smgr.explore(find=found_path, avoid=abort_path)

    if smgr.found:
        final_state = smgr.found[0]
        val1 = final_state.solver.eval(bv1)
        val2 = final_state.solver.eval(bv2)
        print('flag:', val1, val2)
    else:
        print('no flag')

if __name__ == '__main__':
    execute()

#1704280884 2382341151