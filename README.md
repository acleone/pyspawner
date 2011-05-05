# Build #

    $ pushd deps/sha2-1.0
    $ cc -O2 -DSHA2_UNROLL_TRANSFORM -Wall -o sha2 sha2prog.c sha2.c
    $ ./sha2test.pl
    $ popd
    
    $ pushd deps/libev-4.04
    $ ./configure
    $ popd
    
    $ make
    $ make slap


# Test #

    $ ./pyspawner
    
    # in another window:
    $ ./pyspawner-slap 1 1 1


# Misc #

    >>> import distutils.sysconfig
    >>> distutils.sysconfig.get_config_var('LINKFORSHARED')
    '-Xlinker -export-dynamic'

    $ strace -ff -o run_func.out ./pyspawner


## Increasing the number of fds ##

http://www.cs.wisc.edu/condor/condorg/linux_scalability.html
