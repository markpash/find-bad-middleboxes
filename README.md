# find-bad-middleboxes

This is the proof-of-concept code that accompanies the eBPF Summit lightning talk I gave called Bad middlebox!

You can try this yourself to see if anyone connecting to you over IPv6 has a bad middlebox that alters their flow labels.
This also functions as an example of using the cilium/ebpf bpf2go project to compile and embed eBPF objects in go code.
