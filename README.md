3snake - dump sshd and sudo credential related strings
---




About
---
Targeting rooted servers, reads memory from `sshd` and `sudo` system calls that handle passowrd based authentication. Doesn't write any memory to the traced processes. Spawns a new process for every `sshd` and `sudo` command that is run.

Listens for the `proc` event using netlink sockets to get candidate processes to trace. When it receives an `sshd` or `sudo` process `ptrace` is attached and traces `read` and `write` system calls, extracting strings related to password based authentication.

Don't really like the solution of backdooring openssh or installing a kernel module on target servers so I made this.

![3snake](https://user-images.githubusercontent.com/20363764/35941544-74b2d22c-0c07-11e8-887a-474cb9b6daec.gif)










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











