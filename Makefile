# stone		simple repeater
# Copyright(c)1995-2004 by Hiroaki Sengoku <sengoku@gcd.org>
#
# -DUSE_POP	use POP -> APOP conversion
# -DUSE_SSL	use OpenSSL
# -DCPP		preprocessor for reading config. file
# -DIGN_SIGTERM	ignore SIGTERM signal
# -DUNIX_DAEMON	fork into background and become a UNIX Daemon
# -DNO_BCOPY	without bcopy(3)
# -DNO_SNPRINTF	without snprintf(3)
# -DNO_SYSLOG	without syslog(2)
# -DNO_RINDEX	without rindex(3)
# -DNO_THREAD	without thread
# -DNO_PID_T	without pid_t
# -DNO_ADDRINFO without getaddrinfo
# -DPTHREAD     use Posix Thread
# -DPRCTL	use prctl(2) - operations on a process
# -DOS2		OS/2 with EMX
# -DWINDOWS	Windows95/98/NT
# -DNT_SERVICE	WindowsNT/2000 native service

CFLAGS=		# -g

SSL=		/usr/local/ssl
SSL_FLAGS=	-DUSE_SSL -I$(SSL)/include
SSL_LIBS=	-L$(SSL)/lib -lssl -lcrypto

POP_FLAGS=	-DUSE_POP
POP_LIBS=	md5c.o

SVC_LIBS=	logmsg.o

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
	@echo "win-svc   ; for Windows NT service with VC++"
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

stone.exe: stone.c
	$(CC) $(CFLAGS) $(FLAGS) $? $(LIBS)

pop_stone.exe: md5c.obj
	$(MAKE) FLAGS=-DUSE_POP LIBS="md5c.obj" $(TARGET)

ssl_stone.exe:
	$(MAKE) FLAGS="-DUSE_POP -DUSE_SSL" LIBS="ssleay32.lib libeay32.lib" $(TARGET)
#	$(MAKE) FLAGS=-DUSE_SSL LIBS="ssl32.lib crypt32.lib" $(TARGET)

svc_stone.exe: logmsg.res
	$(MAKE) FLAGS="/DNT_SERVICE $(FLAGS)" LIBS="logmsg.res advapi32.lib user32.lib gdi32.lib shell32.lib kernel32.lib" $(TARGET)

logmsg.rc: logmsg.mc
	mc $?

logmsg.o: logmsg.rc
	windres $? -o $@

svc_stone: logmsg.rc $(SVC_LIBS)
	$(MAKE) FLAGS="-DNT_SERVICE $(FLAGS) $(POP_FLAGS) $(SSL_FLAGS)" LIBS="$(LIBS) $(SSL_LIBS) $(SVC_LIBS) -ladvapi32 -luser32 -lgdi32 -lshell32 -lkernel32" $(TARGET)

linux:
	$(MAKE) FLAGS="-DCPP='\"/usr/bin/cpp -traditional\"' -DPTHREAD -DUNIX_DAEMON -DPRCTL -DSO_ORIGINAL_DST=80 -DUSE_EPOLL $(FLAGS)" LIBS="-lpthread $(LIBS)" stone

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
	$(MAKE) FLAGS="-DCPP='\"/usr/bin/cpp -traditional\"' -D_THREAD_SAFE -DPTHREAD -DREG_NOERROR=0 $(FLAGS)" LIBS="-pthread $(LIBS)" stone

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
	$(MAKE) CC=gcc FLAGS="-DNO_ADDRINFO -DNO_SNPRINTF -DIGN_SIGTERM -DCPP='\"/usr/lib/cpp\"' $(FLAGS)" stone

sun-pop:
	$(MAKE) TARGET=sun pop_stone

sun-ssl:
	$(MAKE) TARGET=sun ssl_stone

solaris:
	$(MAKE) CC=gcc FLAGS="-DPTHREAD $(FLAGS)" LIBS="-lnsl -lsocket -lpthread $(LIBS)" stone

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
	$(MAKE) FLAGS="/Zi /DWINDOWS /DNO_RINDEX /DNO_SNPRINTF /DNO_VSNPRINTF /DNO_PID_T $(FLAGS)" LIBS="/MT wsock32.lib $(LIBS) /link /NODEFAULTLIB:LIBC" stone.exe

win-pop:
	$(MAKE) TARGET=win pop_stone.exe

win-ssl:
	$(MAKE) TARGET=win ssl_stone.exe

win-svc:
	$(MAKE) TARGET=win svc_stone.exe

mingw.exe: stone.c
	$(CC) $(CFLAGS) $(FLAGS) -o stone.exe $? $(LIBS)

mingw:
	$(MAKE) CC=gcc FLAGS="-DWINDOWS -DNO_RINDEX -DADDRCACHE $(FLAGS)" LIBS="-lws2_32 -lregex $(LIBS)" mingw.exe

mingw-pop:
	$(MAKE) CC=gcc TARGET=mingw pop_stone

mingw-ssl: cryptoapi.o
	$(MAKE) CC=gcc SSL_FLAGS="$(SSL_FLAGS) -DCRYPTOAPI" SSL_LIBS="cryptoapi.o -lcrypt32 -lssl32 -leay32" TARGET=mingw ssl_stone

mingw-me:
	$(MAKE) CC=gcc SSL_FLAGS="$(SSL_FLAGS) -DNO_ADDRINFO" SSL_LIBS="-lcrypt32 -lssl32 -leay32" TARGET=mingw ssl_stone

mingw-nt:
	$(MAKE) CC=gcc SSL_FLAGS="$(SSL_FLAGS) -DCRYPTOAPI -DNO_ADDRINFO" SSL_LIBS="cryptoapi.o -lcrypt32 -lssl32 -leay32" TARGET=mingw svc_stone

mingw-svc:
	$(MAKE) CC=gcc SSL_FLAGS="$(SSL_FLAGS) -DCRYPTOAPI" SSL_LIBS="cryptoapi.o -lcrypt32 -lssl32 -leay32" TARGET=mingw svc_stone

emx:
	$(MAKE) CC=gcc FLAGS="-DOS2 -Zmts -Zsysv-signals $(FLAGS)" LIBS="$(LIBS) -lsocket" stone.exe

emx-pop:
	$(MAKE) TARGET=emx pop_stone

emx-ssl:
	$(MAKE) TARGET=emx ssl_stone
