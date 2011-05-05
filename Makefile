PROGRAM = pyspawner
OPT = -g -O3
OPT_DEBUG = -g -O0

CFLAGS += -Wall -Werror -Wno-strict-aliasing -Wno-inline
CFLAGS += -DLOG_LEVEL=999
CFLAGS += -iquote src/lib
SLAP_CFLAGS  = -Wall -Werror -Wno-strict-aliasing
SLAP_CFLAGS += -DLOG_LEVEL=0
SLAP_CFLAGS += -iquote src/lib
SLAP_CFLAGS += -lpthread

# see http://docs.python.org/extending/embedding.html

CFLAGS += -I /usr/include/python2.6
LIBS += -lpython2.6

CFILES = 					\
	src/lib/lib.c			\
	src/lib/maxfd.c			\
	src/lib/rbuf.c			\
	src/lib/writeq.c		\
	src/auth.c				\
	src/client.c			\
	src/config.c			\
	src/msg.c				\
	src/pyenv.c				\
	src/pyspawner.c			\
	src/server.c			\
	src/session.c			\
	src/tick.c				\
	src/worker.c

SLAP_CFILES = 				\
	src/lib/lib.c			\
	src/lib/maxfd.c			\
	src/lib/rbuf.c			\
	src/lib/writeq.c		\
	src/auth.c				\
	src/msg.c				\
	src/pyspawner-slap.c

# ================== sha2 ==============================
SHA2_DIR = deps/sha2-1.0
SHA2_CFILES = $(SHA2_DIR)/sha2.c
SHA2_CFLAGS = -DSHA2_UNROLL_TRANSFORM
CFLAGS += $(SHA2_CFLAGS)
CFLAGS += -I $(SHA2_DIR)
SLAP_CFLAGS += $(SHA2_CFLAGS)
SLAP_CFLAGS += -I $(SHA2_DIR)


# ================== libev ==============================
EV_DIR = deps/libev-4.04
EV_CFILES  = $(EV_DIR)/ev.c
EV_CFLAGS  = -DEV_MULTIPLICITY=0 -DEV_EMBED_ENABLE=0 -DEV_STAT_ENABLE=0
EV_CFLAGS += -DEV_PREPARE_ENABLE=0 -DEV_CHECK_ENABLE=0 -DEV_FORK_ENABLE=0
EV_CFLAGS += -DEV_SIGNAL_ENABLE=1 -DEV_ASYNC_ENABLE=0
EV_CFLAGS += -DEV_CHILD_ENABLE=1 -DEV_PID_HASHSIZE=1024
EV_CFLAGS += -DEV_VERIFY=0
EV_CFLAGS += -lm
CFLAGS += $(EV_CFLAGS)
CFLAGS += -I $(EV_DIR)

SLAP_EV_CFLAGS  = -DEV_MULTIPLICITY=1 -DEV_EMBED_ENABLE=0 -DEV_STAT_ENABLE=0
SLAP_EV_CFLAGS += -DEV_PREPARE_ENABLE=0 -DEV_CHECK_ENABLE=0 -DEV_FORK_ENABLE=0
SLAP_EV_CFLAGS += -DEV_SIGNAL_ENABLE=0 -DEV_ASYNC_ENABLE=0
SLAP_EV_CFLAGS += -DEV_CHILD_ENABLE=0
SLAP_EV_CFLAGS += -DEV_VERIFY=0
SLAP_EV_CFLAGS += -lm
SLAP_CFLAGS += $(SLAP_EV_CFLAGS)
SLAP_CFLAGS += -I $(EV_DIR)

.PHONY: all
all: $(PROGRAM)

$(PROGRAM): ev.o sha2.o $(CFILES)
	$(CC) $(CFLAGS) $(OPT) -o $(PROGRAM) $(CFILES) $(LIBS) ev.o sha2.o
	
.PHONY: slap
slap: $(PROGRAM)-slap
	
$(PROGRAM)-slap: ev-slap.o sha2.o $(SLAP_CFILES)
	$(CC) $(SLAP_CFLAGS) $(OPT) -o $(PROGRAM)-slap $(SLAP_CFILES) ev-slap.o sha2.o

ev.o:
	$(CC) $(EV_CFLAGS) $(OPT) -o ev.o -c $(EV_CFILES)
	
ev-slap.o:
	$(CC) $(SLAP_EV_CFLAGS) $(OPT) -o ev-slap.o -c $(EV_CFILES)
	
sha2.o:
	$(CC) $(SHA2_CFLAGS) $(OPT) -o sha2.o -c $(SHA2_CFILES)

	
.PHONY: clean
clean:
	rm -f ev.o ev-slap.o sha2.o