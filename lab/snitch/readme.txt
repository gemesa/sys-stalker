# 1. terminal
$ gcc snitch.c -o snitch
$ ./snitch
PID: 50389
...

# 2. terminal
$ nc -lk 8080
System Info: Linux fedora 6.10.7-200.fc40.x86_64 #1 SMP PREEMPT_DYNAMIC Fri Aug 30 00:08:59 UTC 2024 x86_64, Process ID: 50389

# 3. terminal
$ python trace_snitch.py 50389
...
Attached to getpid
Attached to uname
Attached to send
Attached to getaddrinfo
TIME(s)            COMM             PID    EVENT
6511.472353000     <...>            50389  uname called
6511.472386000     <...>            50389  getpid called
6511.472508000     <...>            50389  getaddrinfo nodename: localhost
6511.472511000     <...>            50389  getaddrinfo port: 8080
6511.473857000     <...>            50389  send data: System Info: Linux fedora 6.10.7-200.fc40.x86_64 #1 SMP PREEMPT_DYNAMIC Fri Aug 30 00:08:59 UTC 2024 x86_64, Process ID: 50389
6511.473874000     <...>            50389  send length: 127
