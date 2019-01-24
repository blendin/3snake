3snake - dump sshd and sudo credential related strings
---

About
---
Targeting rooted servers, reads memory from `sshd` and `sudo` system calls that handle password based authentication. Doesn't write any memory to the traced processes. Spawns a new process for every `sshd` and `sudo` command that is run.

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

Daemonize and dump output to file
`./3snake -d -o "/tmp/output_file.txt"`

Configuration
---
Located in [config.h](https://github.com/blendin/3snake/blob/master/src/config.h)  
- __ROOT_DIR__ - root directory when daemonized (relative file paths for -o option will end up here)   
- __ENABLE_SSH__ - OpenSSH server password auth
- __ENABLE_SUDO__ - sudo password auth
- __ENABLE_SU__ (experimental) - su password auth
- __ENABLE_SSH_CLIENT__ (experimental) - ssh client password auth

Limitations
---
Linux, ptrace enabled, /proc filesystem mounted


Todo
---

| Features                                          | X   |
|---------------------------------------------------|-----|
| OpenSSH server password auth                      | X   |
| sudo                                              | X   |
| su                                                | X   |
| regex strings from processes                      | ~   |
| ssh client                                        | X   |

* Make the process of adding tracers more fluid
* Yubikey: Ask for second yubikey from end users, OpenSSH
* Output mode that only shows usernames/passwords

License
---
MIT
