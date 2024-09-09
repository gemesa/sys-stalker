# 1. terminal
$ gcc snitch.c -o snitch
$ ./snitch & pid=$!; kill -STOP $pid
[1] 50389
                                                                                                                      
[1]  + suspended (signal)  ./snitch

# run trace_snitch.py in an other terminal then:
$ kill -CONT 50389 && reptyr 50389
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
