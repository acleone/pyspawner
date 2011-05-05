/*
 * pyenv.c
 *
 *  Created on: Feb 19, 2011
 *      Author: alex
 */

#include <Python.h>

#include <ev.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>


#include "config.h"
#include "def.h"
#include "pyenv.h"

#if 1

static PyObject *globals, *main_module, *run_func;
static struct sigaction py_sigint;

static int
pyenv_run_path(const char *path)
{
    FILE *fp;
    PyObject *rv;

    fp = fopen(path, "r");
    EXIT_ON_NULL_FMT(fp, "fopen(\"%s\", \"r\")", path);

    rv = PyRun_File(fp, path, Py_file_input, globals, globals);
    fclose(fp);
    if (rv == NULL) {
        PyErr_Print();
        return -1;
    }
    return 0;
}
/*
 * sets SIGINT.
 */
static void
pyenv_init_python()
{
    PyObject *sys_path, *py_dir_path;
    LOGF(0, "Initializing python environment and running '%s'...\n",
         config.pyenv_init_path);
    Py_Initialize();
    EXIT_ON_NEG(sigaction(SIGINT, NULL, &py_sigint));

    EXIT_ON_NULL(sys_path = PySys_GetObject("path"));
    EXIT_ON_NULL(py_dir_path = PyString_FromString("./src/python"));
    EXIT_ON_NEG(PyList_Append(sys_path, py_dir_path));

    EXIT_ON_NULL(main_module = PyImport_AddModule("__main__"));
    EXIT_ON_NULL(globals = PyModule_GetDict(main_module));

    if (pyenv_run_path(config.pyenv_init_path) < 0) {
        Py_Finalize();
        exit(EXIT_FAILURE);
    }

    run_func = PyObject_GetAttrString(main_module, config.pyenv_run_func);
    if (run_func == NULL || !PyCallable_Check(run_func)) {
        if (PyErr_Occurred()) {
            PyErr_Print();
        }
        LOGF(0, "no function named '%s' in '%s'.\n",
             config.pyenv_run_func, config.pyenv_init_path);
        exit(EXIT_FAILURE);
    }

    DEBUGF(6, "After '%s', globals contains %d objects\n",
           config.pyenv_init_path, (int)PyDict_Size(globals));
}

void
pyenv_sysinit(EV_P)
{
    pyenv_init_python();
}

void
pyenv_sysuninit(EV_P)
{
    Py_Finalize();
}

void
pyenv_child_after_fork()
{
    // reinstall the keyboard interrupt handler instead of the ev_signal
    // in main.
    ASSERT(run_func != NULL);

    EXIT_ON_NEG(sigaction(SIGINT, &py_sigint, NULL));
    PyOS_AfterFork();
    PyObject_CallObject(run_func, NULL);
    if (PyErr_Occurred()) {
        PyErr_Print();
    }
    Py_Finalize();
    exit(EXIT_SUCCESS);
}

#else

void
pyenv_loop_init(EV_P)
{

}

void
pyenv_loop_uninit(EV_P)
{

}

void
pyenv_child_after_fork()
{
    exit(EXIT_SUCCESS);
}

#endif
