import angr

def main():
    
    p = angr.Project('../problems/00_angr_find')
    
    initial_state = p.factory.entry_state()
    sim = p.factory.simgr(initial_state)
    target_address = 0x804867d
    sim.explore(find=target_address)

    if sim.found:
        solution = sim.found[0]
        print('Flag: ', solution.posix.dumps(0))
    else:
        print('Ghey')

if __name__ == '__main__':
   main()


#JXWVXRKX