import angr
import sys

def found_path(state):
    return b'Good Job.' in state.posix.dumps(1)

def abort_path(state):
    return b'Try again.' in state.posix.dumps(1)

def execute():
    p = angr.Project('../problems/05_angr_symbolic_memory')
    start_addr = 0x080485FE
    blank_state = p.factory.blank_state(addr=start_addr)

    sym_input = blank_state.solver.BVS('sym_input', 8*8)
    sym_pw1 = blank_state.solver.BVS('sym_pw1', 8*8)
    sym_pw2 = blank_state.solver.BVS('sym_pw2', 8*8)
    sym_pw3 = blank_state.solver.BVS('sym_pw3', 8*8)

    blank_state.memory.store(0x0A1BA1C0, sym_input)
    blank_state.memory.store(0x0A1BA1C8, sym_pw1)
    blank_state.memory.store(0x0A1BA1D0, sym_pw2)
    blank_state.memory.store(0x0A1BA1D8, sym_pw3)

    smgr = p.factory.simgr(blank_state)
    smgr.explore(find=found_path, avoid=abort_path)

    if smgr.found:
        final_state = smgr.found[0]
        val_input = final_state.solver.eval(sym_input, cast_to=bytes)
        val_pw1 = final_state.solver.eval(sym_pw1, cast_to=bytes)
        val_pw2 = final_state.solver.eval(sym_pw2, cast_to=bytes)
        val_pw3 = final_state.solver.eval(sym_pw3, cast_to=bytes)
        print('flag:', val_input, val_pw1, val_pw2, val_pw3)
    else:
        raise Exception('Could not find flag')

if __name__ == '__main__':
    execute()

#NAXTHGNR JVSFTPWE LMGAUHWC XMDCPALU