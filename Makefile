# stone		simple repeater
# Copyright(c)1995-1999 by Hiroaki Sengoku <sengoku@gcd.org>
#
# -DUSE_POP	use POP -> APOP conversion
# -DUSE_SSL	use OpenSSL
# -DCPP		preprocessor for reading config. file
# -DH_ERRNO	h_errno is not defined in header files
# -DIGN_SIGTERM	ignore SIGTERM signal
# -DINET_ADDR	use custom inet_addr(3)
# -DNO_ALRM	without SIGALRM signal
# -DNO_BCOPY	without bcopy(3)
# -DNO_SNPRINTF	without snprintf(3)
# -DNO_SYSLOG	without syslog(2)
# -DNO_THREAD	without thread
# -DOS2		OS/2 with EMX
# -DWINDOWS	Windows95/98/NT
# -DNT_SERVICE	WindowsNT/2000 native service
# -DUNIX_DAEMON	fork into background and become a UNIX Daemon

CFLAGS=		# -g

SSL=		/usr/local/ssl
SSL_FLAGS=	-DUSE_SSL -I$(SSL)/include
SSL_LIBS=	-L$(SSL)/lib -lssl -lcrypto

POP_FLAGS=	-DUSE_POP
POP_LIBS=	md5c.o

SVC_LIBS=	logmsg.o service.o svcbody.o

all:
	@echo "run make with one of the following arguments"
	@echo "linux     ; for Linux"
	@echo "zaurus    ; for Linux Zaurus"
	@echo "bsd       ; for FreeBSD or BSD/OS"
	@echo "macosx    ; for Mac OS X"
	@echo "sun       ; for SunOS 4.x with gcc"
	@echo "solaris   ; for Solaris with gcc"
	@echo "hp        ; for HP-UX with gcc"
	@echo "irix      ; for IRIX"
	@echo "win       ; for Windows 95/NT with VC++"
	@echo "mingw     ; for Windows 95/NT with MinGW"
	@echo "mingw-svc ; for Windows NT service with MinGW"
	@echo "emx       ; for OS/2 with EMX"
	@echo "using POP -> APOP conv., add '-pop' (example: linux-pop)"
	@echo "using above conv. and OpenSSL, add '-ssl' (example: linux-ssl)"

clean:
	rm -f stone $(POP_LIBS) stone.exe stone.obj md5c.obj stone.o $(SVC_LIBS) MSG00001.bin logmsg.h logmsg.rc

md5c.c:
	@echo "*** md5c.c is contained in RFC1321"

stone: stone.c
	$(CC) $(CFLAGS) $(FLAGS) -o $@ $? $(LIBS)

pop_stone: $(POP_LIBS)
	$(MAKE) FLAGS="$(POP_FLAGS)" LIBS="$(POP_LIBS)" $(TARGET)

ssl_stone:
	$(MAKE) FLAGS="$(POP_FLAGS) $(SSL_FLAGS)" LIBS="$(LIBS) $(SSL_LIBS)" $(TARGET)

logmsg.rc: logmsg.mc
	mc $?

logmsg.o: logmsg.rc
	windres $? -o $@

svc_stone: logmsg.rc stone.o $(SVC_LIBS)
	$(CC) -o stone.exe stone.o $(SVC_LIBS) $(SSL_LIBS) -lwsock32 -ladvapi32 -luser32 -lgdi32 -lshell32 -lkernel32

stone.exe: stone.c
	$(CC) $(FLAGS) $? $(LIBS)

pop_stone.exe: md5c.obj
	$(MAKE) FLAGS=-DUSE_POP LIBS="md5c.obj" $(TARGET)

ssl_stone.exe:
	$(MAKE) FLAGS="-DUSE_POP -DUSE_SSL" LIBS="ssleay32.lib libeay32.lib" $(TARGET)
#	$(MAKE) FLAGS=-DUSE_SSL LIBS="ssl32.lib crypt32.lib" $(TARGET)

linux:
	$(MAKE) FLAGS="-DINET_ADDR -DCPP='\"/usr/bin/cpp -traditional\"' -DPTHREAD -DUNIX_DAEMON -DPRCTL $(FLAGS)" LIBS="-lpthread $(LIBS)" stone

linux-pop:
	$(MAKE) TARGET=linux pop_stone

linux-ssl:
	$(MAKE) TARGET=linux ssl_stone LIBS="-ldl"

zaurus:
	$(MAKE) CC="arm-linux-gcc" FLAGS="-DPTHREAD -DUNIX_DAEMON $(FLAGS)" LIBS="-lpthread $(LIBS)" stone
	arm-linux-strip stone

zaurus-pop:
	$(MAKE) CC="arm-linux-gcc" TARGET=zaurus pop_stone

zaurus-ssl:
	$(MAKE) CC="arm-linux-gcc" SSL_LIBS="-lssl -lcrypto" TARGET=zaurus ssl_stone

bsd:
	$(MAKE) FLAGS="-DCPP='\"/usr/bin/cpp -traditional\"' -D_THREAD_SAFE -DPTHREAD $(FLAGS)" LIBS="-pthread $(LIBS)" stone

bsd-pop:
	$(MAKE) TARGET=bsd pop_stone

bsd-ssl:
	$(MAKE) TARGET=bsd ssl_stone

macosx:
	$(MAKE) FLAGS="-DCPP='\"/usr/bin/cpp -traditional\"' -D_THREAD_SAFE -DPTHREAD $(FLAGS)" stone

macosx-pop:
	$(MAKE) TARGET=macosx pop_stone

macosx-ssl:
	$(MAKE) TARGET=macosx SSL=/usr ssl_stone

sun:
	$(MAKE) CC=gcc FLAGS="-DINET_ADDR -DNO_SNPRINTF -DIGN_SIGTERM -DCPP='\"/usr/lib/cpp\"' $(FLAGS)" stone

sun-pop:
	$(MAKE) TARGET=sun pop_stone

sun-ssl:
	$(MAKE) TARGET=sun ssl_stone

solaris:
	$(MAKE) CC=gcc FLAGS="-DNO_SNPRINTF $(FLAGS)" LIBS="-lnsl -lsocket $(LIBS)" stone

solaris-pop:
	$(MAKE) TARGET=solaris pop_stone

solaris-ssl:
	$(MAKE) TARGET=solaris ssl_stone

hp:
	$(MAKE) CC=gcc FLAGS="-DNO_SNPRINTF -DH_ERRNO -DCPP='\"/lib/cpp\"' $(FLAGS)" stone

hp-pop:
	$(MAKE) TARGET=hp pop_stone

hp-ssl:
	$(MAKE) TARGET=hp ssl_stone

irix:
	$(MAKE) FLAGS="-DNO_SNPRINTF $(FLAGS)" stone

irix-pop:
	$(MAKE) TARGET=irix pop_stone

irix-ssl:
	$(MAKE) TARGET=irix ssl_stone

win:
	$(MAKE) FLAGS="-DWINDOWS $(FLAGS)" LIBS="/MT wsock32.lib $(LIBS) /link /NODEFAULTLIB:LIBC" stone.exe

win-pop:
	$(MAKE) TARGET=win pop_stone.exe

win-ssl:
	$(MAKE) TARGET=win ssl_stone.exe

mingw.exe: stone.c
	$(CC) $(FLAGS) -o stone.exe $? $(LIBS)

mingw:
	$(MAKE) CC=gcc FLAGS="-DWINDOWS $(FLAGS)" LIBS="-lwsock32 $(LIBS)" mingw.exe

mingw-pop:
	$(MAKE) CC=gcc TARGET=mingw pop_stone

mingw-ssl:
	$(MAKE) CC=gcc FLAGS="$(SSL_FLAGS)" SSL_LIBS="-LC:/mingw/lib/openssl -lssl32 -leay32 -lregex" TARGET=mingw ssl_stone

mingw-svc:
	$(MAKE) CC=gcc CFLAGS="-DWINDOWS -DNT_SERVICE $(POP_FLAGS) $(SSL_FLAGS) $(CFLAGS)" SSL_LIBS="-LC:/mingw/lib/openssl -lssl32 -leay32 -lregex" TARGET=mingw svc_stone

emx:
	$(MAKE) CC=gcc FLAGS="-DOS2 -Zmts -Zsysv-signals $(FLAGS)" LIBS="$(LIBS) -lsocket" stone.exe

emx-pop:
	$(MAKE) TARGET=emx pop_stone

emx-ssl:
	$(MAKE) TARGET=emx ssl_stone
