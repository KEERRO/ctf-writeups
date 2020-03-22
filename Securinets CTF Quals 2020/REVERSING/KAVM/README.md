# KAVM (985 pts)

Given a 32bit stripped binary. The title of the challenge itself tells us that it's a VM protected binary.


There are 2 approaches for this challenge:

1st:

Follow the VM code and write a disassembler in python or other programming language to simulate the execution flow.

2nd:

Use angr to solve the challenge and thank to [Mohamed aziz knani](https://twitter.com/moonflock) (member of ```from Sousse, with love``` team ranked 5th during the ctf) who provided the angr solver:

```python
import angr
import claripy

p = angr.Project("./kavm")

symsize = claripy.BVS('inputLength', 32)

line = [ ]
for j in range(32):
    line.append(claripy.BVS('x{}'.format(j), 8))

bytestring = claripy.Concat(*line)
print(bytestring)
simfile = angr.SimFile('/tmp/stdin', bytestring, size=symsize)
state = p.factory.entry_state(stdin=simfile)
simgr = p.factory.simulation_manager(state)

for i in bytestring.chop(8):
    print(i)
    state.solver.add(
        
            state.solver.And(
                i >= ord(' '),
                i <= ord('~')))

state.solver.add(bytestring.chop(8)[0] == ord('s'))
state.solver.add(bytestring.chop(8)[1] == ord('e'))
state.solver.add(bytestring.chop(8)[2] == ord('c'))
state.solver.add(bytestring.chop(8)[3] == ord('u'))
state.solver.add(bytestring.chop(8)[4] == ord('r'))
state.solver.add(bytestring.chop(8)[5] == ord('i'))
state.solver.add(bytestring.chop(8)[6] == ord('n'))
state.solver.add(bytestring.chop(8)[7] == ord('e'))
state.solver.add(bytestring.chop(8)[8] == ord('t'))
state.solver.add(bytestring.chop(8)[9] == ord('s'))
state.solver.add(bytestring.chop(8)[10] == ord('{'))

simgr.explore(find=lambda s: b"Good" in s.posix.dumps(1))
print(simgr.stashes)
f = simgr.found[0]
print(f)
print((b"STDOUT: "+f.posix.dumps(1)))
print((b"FLAG: "+f.posix.dumps(0)))
```

```FLAG : securinets{vm_pr0t3ct10n_r0ck5!}```
