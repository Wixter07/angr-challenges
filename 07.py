import angr
import sys

def found_path(state):
    return b'Good Job.' in state.posix.dumps(1)

def abort_path(state):
    return b'Try again.' in state.posix.dumps(1)

def execute():
    P = angr.Project('../problems/07_angr_symbolic_file')
    start_addr = 0x080488E7
    blank_state = P.factory.blank_state(addr=start_addr)

    filename = 'OJKSQYDP.txt'
    sym_file_size = 64

    sym_pw = blank_state.solver.BVS('sym_pw', sym_file_size * 8)

    sym_file = angr.storage.SimFile(filename, content=sym_pw, size=sym_file_size)
    blank_state.fs.insert(filename, sym_file)

    smgr = P.factory.simgr(blank_state)
    smgr.explore(find=found_path, avoid=abort_path)

    if smgr.found:
        final_state = smgr.found[0]
        print('flag:', final_state.solver.eval(sym_pw, cast_to=bytes))
    else:
        print('Ghey')

if __name__ == '__main__':
    execute()

