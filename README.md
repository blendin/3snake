3snake - dump sshd and sudo credential related strings
---




About
---
Reads memory from `sshd` and `sudo` system calls that handle passowrd based authentication. Doesn't write any memory to the 3snake process. Spawns a new process for every `sshd` and `sudo` command that is run. Uses proc event from netlink sockets to get candidate processes to trace.

Don't really like the solution of backdooring openssh or installing a kernel module on target servers.

![3snake](https://user-images.githubusercontent.com/20363764/35939498-29bed190-0c01-11e8-9e14-09516bd8ea2a.gif)






Build
---
```sh
make
./3snake -h
./3snake
```




Usage
---

Run in current terminal
`./3snake`

Run in current terminal and dump output to file
`./3snake -o "output_file.txt"`

Daemonize and dump output to file
`./3snake -d -o "output_file.txt"`





Deps
---
Linux, ptrace enabled, /proc filesystem mounted



Todo
---

| Features                                          | X   |
|---------------------------------------------------|-----|
| OpenSSH server password auth                      | X   |
| sudo                                              | X   |
| su                                                | ~   |
| regex strings from processes                      | ~   |
| ssh client                                        | ~   |

* Make the process of adding tracers more fluid
* Yubikey: Ask for second yubikey from end users, OpenSSH
* Output mode that only shows usernames/passwords




License
---
MIT







