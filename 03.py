import angr 
import claripy
import sys

def execute():
    p = angr.Project('../problems/03_angr_symbolic_registers')
    start_addr = 0x08048980
    blank_state = p.factory.blank_state(addr=start_addr)

    bv0 = claripy.BVS('bv0', 32)
    bv1 = claripy.BVS('bv1', 32)
    bv2 = claripy.BVS('bv2', 32)

    blank_state.regs.eax = bv0
    blank_state.regs.ebx = bv1
    blank_state.regs.edx = bv2

    smgr = p.factory.simgr(blank_state)
    smgr.explore(find=found_path, avoid=abort_path)

    if smgr.found:
        final_state = smgr.found[0]
        val0 = final_state.solver.eval(bv0)
        val1 = final_state.solver.eval(bv1)
        val2 = final_state.solver.eval(bv2)
        print('flag:', hex(val0), hex(val1), hex(val2))
    else:
        print('no flag')

def found_path(state):
    return b"Good Job." in state.posix.dumps(1)

def abort_path(state):
    return b"Ghey" in state.posix.dumps(1)

if __name__ == '__main__':
    execute()
