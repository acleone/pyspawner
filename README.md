Purpose
=======

pyspawner is meant as the backend of an online python interpreter.  An online
python interpreter could be as simple as a webpage with textbox and an
'execute' button, that runs the python on the server and sends the output
back, and saves the interpreter's state.

For complex environments, there could be lots of builtins that are imported
before the client's script is run.  For example, if no imports are required
for plotting, and the user can just run:

    plot(lambda x: x^2, (-1, 1))

If the environment is pretty complex, then it will take a while to set up, and
an newly setup environment could take up megabytes of memory.  If the server
has lots of concurrent idle users, then it better have lots of memory.

This project tries to solve some of these problems by forking an environment
for each new client.  Thanks to Copy-on-write, the new environment will barely
use any memory until it's modified.

Any output from the forked worker process is sent to the client in
type-length-value encoded messages, and clients can send messages to the worker
process' stdin.

Overview
========

* src/pyspawner.c - The main eventloop.
* src/server.c - socket for accept()-ing clients.
* src/client.c - Client interaction.
* src/auth.c - Client authentication.
* src/pyenv.c - The python execution environment.
* src/worker.c - Forks and communicates with worker processes.
* src/pyspawner-slap.c - Stress testing.

Build
=====

    $ pushd deps/sha2-1.0
    $ cc -O2 -DSHA2_UNROLL_TRANSFORM -Wall -o sha2 sha2prog.c sha2.c
    $ ./sha2test.pl
    $ popd
    
    $ pushd deps/libev-4.04
    $ ./configure
    $ popd
    
    $ make
    $ make slap


Test
====

    $ ./pyspawner
    
    # in another window:
    $ ./pyspawner-slap 1 1 1


Misc
====

    >>> import distutils.sysconfig
    >>> distutils.sysconfig.get_config_var('LINKFORSHARED')
    '-Xlinker -export-dynamic'

    $ strace -ff -o run_func.out ./pyspawner


Increasing the number of allowable fds: http://www.cs.wisc.edu/condor/condorg/linux_scalability.html
