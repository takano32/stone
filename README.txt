
			    Simple Repeater

			   stone version 2.2c

		Copyright(c)1995-2004 by Hiroaki Sengoku
			    sengoku@gcd.org


  stone $B$O!"%"%W%j%1!<%7%g%s%l%Y%k$N(B TCP & UDP $B%Q%1%C%H%j%T!<%?!<$G$9!#(B
$B%U%!%$%"%&%)!<%k$NFb$+$i30$X!"$"$k$$$O30$+$iFb$X!"(BTCP $B%Q%1%C%H$"$k$$$O(B 
UDP $B%Q%1%C%H$rCf7Q$7$^$9!#(B

  stone $B$K$O0J2<$N$h$&$JFCD'$,$"$j$^$9!#(B

1. Win32 $B$KBP1~$7$F$$$k(B
	$B0JA0$O(B UNIX $B%^%7%s$G9=@.$5$l$k$3$H$,B?$+$C$?%U%!%$%"%&%)!<%k$G$9(B
	$B$,!":G6a$O(B WindowsNT $B$,;H$o$l$k%1!<%9$,A}$($F$-$^$7$?!#(Bstone $B$O(B 
	WindowsNT $B$"$k$$$O(B Windows95 $B>e$G<j7Z$K<B9T$9$k$3$H$,$G$-$^$9!#(B
	$B$b$A$m$s!"(BLinux, FreeBSD, BSD/OS, SunOS, Solaris, HP-UX $B$J$I$N(B 
	UNIX $B%^%7%s$G$b;H$&$3$H$,$G$-$^$9!#(B

2. $BC1=c(B
	$B$o$:$+(B 5000 $B9T(B (C $B8@8l(B) $B$G$9$N$G!"%;%-%e%j%F%#%[!<%k$,@8$8$k2DG=(B
	$B@-$r:G>.8B$K$G$-$^$9!#(B

3. SSL $BBP1~(B
	OpenSSL (http://www.openssl.org/) $B$r;H$&$3$H$K$h$j!"0E9f2=(B/$BI|9f(B
	$B$7$F%Q%1%C%H$rCf7Q$G$-$^$9!#$^$?!"%/%i%$%"%s%HG'>Z!"$"$k$$$O(B $B%5!<(B
	$B%PG'>Z$r9T$J$$!">ZL@=q$N%5%V%8%'%/%H$N0lIt$rCf7Q@h$XAw$k$3$H$,$G(B
	$B$-$^$9!#(B

4. http proxy
	$B4J0W7?(B http proxy $B$H$7$F$b;H$&$3$H$,$G$-$^$9!#(B

5. POP -> APOP $BJQ49(B
	APOP $B$KBP1~$7$F$$$J$$%a!<%i$H(B stone $B$r;H$&$3$H$G!"(BAPOP $B%5!<%P$X(B
	$B%"%/%;%9$G$-$^$9!#(B


$B;HMQJ}K!(B

	stone [-C <file>] [-P <command>] [-Q <options>] [-d] [-p] [-n]
	      [-u <max>] [-f <n>] [-l] [-L <file>] [-a <file>] [-i <file>]
	      [-X <n>] [-T <n>] [-r]
	      [-b <n> <master>:<port> <backup>:<port>]
	      [-B <host>:<port> <host1>:<port1>... --]
	      [-o <n>] [-g <n>] [-t <dir>] [-D] [-c <dir>]
	      [-q <SSL>] [-z <SSL>]
	      <st> [-- <st>]...

	-C $B$O%*%W%7%g%s$*$h$S(B <st> $B$r%3%^%s%I%i%$%s$G;XDj$9$k$+$o$j$K@_(B
	$BDj%U%!%$%k$+$iFI$_9~$_$^$9!#(B-P $B$O@_Dj%U%!%$%k$rFI$_9~$`:]$N%W%j(B
	$B%W%m%;%C%5$r;XDj$7$^$9!#%W%j%W%m%;%C%5$XM?$($k0z?t$O(B -Q $B$G;XDj$G(B
	$B$-$^$9!#(B

	$B%*%W%7%g%s$H$7$F(B -d $B$r;XDj$9$k$H!"%G%P%C%0%l%Y%k$rA}2C$5$;$^$9!#(B 
	-p $B$r;XDj$9$k$HCf7Q$7$?%G!<%?$r%@%s%W$7$^$9!#(B-n $B$r;XDj$9$k$H!"%[(B
	$B%9%HL>$d%5!<%S%9L>$NBe$o$j$K(B IP $B%"%I%l%9$d%5!<%S%9HV9f$rI=<($7$^(B
	$B$9!#(B

	-u $B%*%W%7%g%s$OF1;~$K5-21$G$-$k(B UDP $B%Q%1%C%H$NH/?.85$N:GBg?t$r;X(B
	$BDj$7$^$9!#%G%U%)%k%H$O(B 10 $B$G$9!#(B-f $B%*%W%7%g%s$O;R%W%m%;%9$N?t$r(B
	$B;XDj$7$^$9!#%G%U%)%k%H$O;R%W%m%;%9L5$7$G$9!#(B

	-l $B$r;XDj$9$k$H!"%(%i!<%a%C%;!<%8Ey$r(B syslog $B$X=PNO$7$^$9!#(B-L $B$r(B
	$B;XDj$9$k$H!"%(%i!<%a%C%;!<%8Ey$r(B file $B$X=PNO$7$^$9!#(B-a $B$r;XDj$9(B
	$B$k$H!"%"%/%;%9%m%0$r(B file $B$X=PNO$7$^$9!#(B-i $B$O(B stone $B$N%W%m%;%9(B 
	ID $B$r=PNO$9$k%U%!%$%k$r;XDj$7$^$9!#(B

	-X $B$OCf7Q$r9T$J$&:]$N%P%C%U%!$NBg$-$5$r;XDj$7$^$9!#%G%U%)%k%H$O(B 
	1000 $B%P%$%H$G$9!#(B-T $B$r;XDj$9$k$H(B TCP $B%;%C%7%g%s$N%?%$%`%"%&%H$N(B
	$BIC?t$rJQ99$G$-$^$9!#%G%U%)%k%H$O(B 600 (10 $BJ,(B) $B$G$9!#(B-r $B$r;XDj$9$k(B
	$B$H(B <st> $B$N%=%1%C%H$K(B SO_REUSEADDR $B$r@_Dj$7$^$9!#(B

	-b $B$OCf7Q@h(B <master>:<port> $B$K@\B3$G$-$J$$$H$-$N%P%C%/%"%C%W$H$7(B
	$B$F(B <backup>:<port> $B$r;XDj$7$^$9!#$9$J$o$A(B <n> $BIC$4$H$K(B 
	<master>:<port> $B$K@\B32DG=$+%A%'%C%/$7!"$b$7@\B3IT2D$N>l9g$O!"Cf(B
	$B7Q@h$r(B <backup>:<port> $B$XJQ99$7$^$9!#(B

	-B $B$OCf7Q@h%0%k!<%W$N;XDj$G$9!#Cf7Q@h$,(B <host>:<port> $B$G$"$k>l9g!"(B
	$B$3$N%0%k!<%W$NCf$+$i%i%s%@%`$K0l$D$NCf7Q@h$rA*$s$GCf7Q$7$^$9!#(B

	-o $B$H(B -g $B$O$=$l$>$l%f!<%6(B ID $B$H%0%k!<%W(B ID $B$r;XDj$7$^$9!#(BID $B$O?t(B
	$B;z$N$_;XDj2DG=$G$9!#(B-t $B$r;XDj$9$k$H!"(Bdir $B$X(B chroot $B$7$^$9!#(B-D $B$r(B
	$B;XDj$9$k$H!"(Bstone $B$r%G!<%b%s$H$7$F5/F0$7$^$9!#(B-c $B$O%3%"%@%s%W$r(B
	$B9T$J$&%G%#%l%/%H%j$r;XDj$7$^$9!#(B

	-q $B$*$h$S(B -z $B$O!"(BSSL $B0E9f2=(B/$BI|9f(B $B$N%*%W%7%g%s$G$9!#(B-q $B$O!"(Bstone 
	$B$,(B SSL $B%/%i%$%"%s%H$H$7$F!"B>$N(B SSL $B%5!<%P$X@\B3$9$k$H$-!"$9$J$o(B
	$B$ACf7Q@h$,(B SSL $B%5!<%P$N;~$N!"(BSSL $B%*%W%7%g%s$G$9!#(B-z $B$O(B stone $B$,(B 
	SSL $B%5!<%P$H$7$F!"B>$N(B SSL $B%/%i%$%"%s%H$+$i$N@\B3$r<uIU$1$k;~$N!"(B
	SSL $B%*%W%7%g%s$G$9!#(B

	<SSL> $B$O(B SSL $B%*%W%7%g%s$G!"<!$N$$$:$l$+$G$9!#(B

	default		SSL $B%*%W%7%g%s;XDj$r%G%U%)%k%H$KLa$7$^$9!#(B
			$BJ#?t$N(B <st> $B$r;XDj$9$k:]!"(B<st> $BKh$K0[$J$k(B SSL $B%*(B
			$B%W%7%g%s$r;XDj$9$k$3$H$,$G$-$^$9!#(B
	verbose		$B%G%P%C%0MQJ8;zNs$r%m%0$K=PNO$7$^$9!#(B
	verify		SSL $B@\B3Aj<j$K!"(BSSL $B>ZL@=q$rMW5a$7$^$9!#(B
	verify,once	$B%;%C%7%g%s3+;O;~$K0lEY$@$1!"(B
			SSL $B%/%i%$%"%s%H$K>ZL@=q$rMW5a$7$^$9!#(B(-z $B@lMQ(B)
	verify,ifany	SSL $B%/%i%$%"%s%H$+$i>ZL@=q$,Aw$i$l$F$-$?$H$-$N$_(B
			$BG'>Z$7$^$9!#Aw$i$l$F$3$J$$>l9g$OG'>Z$;$:$K(B
			$B%;%C%7%g%s$r3+;O$7$^$9!#(B(-z $B@lMQ(B)
	verify,none	SSL $B@\B3Aj<j$K(B SSL $B>ZL@=q$rMW5a$7$^$;$s!#(B
	uniq		SSL $B@\B3Aj<j$N(B SSL $B>ZL@=q$N%7%j%"%kHV9f$,A02s$N(B
			$B@\B3$H0[$J$k>l9g!"@\B3$r5qH]$7$^$9!#(B
	re<n>=<regex>	SSL $B>ZL@=q$N%A%'!<%s$,K~$?$9$Y$-@55,I=8=$r;XDj$7$^$9!#(B
			<n> $B$O(B depth $B$G$9!#(Bre0 $B$,>ZL@=q$N%5%V%8%'%/%H!"(B
			re1 $B$,$=$NH/9T<T$r0UL#$7$^$9!#(B
			<n> $B$O(B 9 $B$^$G;XDj$G$-$^$9!#(B
	depth=<n>	SSL $B>ZL@=q%A%'!<%s$ND9$5$N:GBgCM$r;XDj$7$^$9!#(B
			$B%A%'!<%s$ND9$5$,$3$NCM$r1[$($k$HG'>Z$,<:GT$7$^$9!#(B
			<n> $B$N:GBgCM$O(B 9 $B$G$9!#(B
	key=<file>	$B>ZL@=q$NHkL)80%U%!%$%k$r;XDj$7$^$9!#(B
	cert=<file>	$B>ZL@=q%U%!%$%k$r;XDj$7$^$9!#(B
	CAfile=<file>	$BG'>Z6I$N>ZL@=q%U%!%$%k$r;XDj$7$^$9!#(B
	CApath=<dir>	$BG'>Z6I$N>ZL@=q$,$"$k%G%#%l%/%H%j$r;XDj$7$^$9!#(B
	cipher=<list>	$B0E9f2=%"%k%4%j%:%`$N%j%9%H$r;XDj$7$^$9!#(B
	lb<n>=<m>	SSL $B>ZL@=q$N(B CN $B$K1~$8$FCf7Q@h$r@Z$jBX$($^$9!#(B
			SSL $B%*%W%7%g%s$N(B re<n>= $B$G;XDj$7$?@55,I=8=Cf!"(B
			<n> $BHVL\$N(B ( ... ) $BFb$N@55,I=8=$K%^%C%A$7$?J8;z(B
			$BNs$+$i;;=P$7$??tCM$N>jM>(B <m> $B$K4p$E$$$F!"(B-B $B%*%W(B
			$B%7%g%s$G;XDj$7$?Cf7Q@h%0%k!<%W$NCf$+$iCf7Q@h$rA*(B
			$B$S$^$9!#(B

	<st> $B$O<!$N$$$:$l$+$G$9!#(B<st> $B$O!V(B--$B!W$G6h@Z$k$3$H$K$h$j!"J#?t8D(B
	$B;XDj$G$-$^$9!#(B

	(1)	<host>:<port> <sport> [<xhost>...]
	(2)	<host>:<port> <shost>:<sport> [<xhost>...]
	(3)	<display> [<xhost>...]
	(4)	proxy <sport> [<xhost>...]
	(5)	<host>:<port>/http <request> [<xhost>...]
	(6)	<host>:<port>/proxy <header> [<xhost>...]
	(7)	health <sport> [<xhost>...]

	stone $B$r<B9T$7$F$$$k%^%7%s$N%]!<%H(B <sport> $B$X$N@\B3$r!"B>$N%^%7(B
	$B%s(B <host> $B$N%]!<%H(B <port> $B$XCf7Q$7$^$9!#%$%s%?%U%'!<%9$rJ#?t;}$D(B
	$B%^%7%s$G$O!"(B(2) $B$N$h$&$K%$%s%?%U%'!<%9$N%"%I%l%9(B <shost> $B$r;XDj(B
	$B$9$k$3$H$K$h$j!"FCDj$N%$%s%?%U%'!<%9$X$N@\B3$N$_$rE>Aw$9$k$3$H$,(B
	$B$G$-$^$9!#(B

	(3) $B$O!"(BX $B%W%m%H%3%kCf7Q$N$?$a$N>JN,5-K!$G$9!#%G%#%9%W%l%$HV9f(B 
	<display> $B$X$N@\B3$r!"4D6-JQ?t(B DISPLAY $B$G;XDj$7$?(B X $B%5!<%P$XE>Aw(B
	$B$7$^$9!#(B

	(4) $B$O!"(Bhttp proxy $B$G$9!#(BWWW $B%V%i%&%6$N(B http proxy $B$N@_Dj$G!"(B
	stone $B$r<B9T$7$F$$$k%^%7%s$*$h$S%]!<%H(B <sport> $B$r;XDj$7$^$9!#(B

	(5) $B$O!"(Bhttp $B%j%/%(%9%H$K$N$;$F%Q%1%C%H$rCf7Q$7$^$9!#(B<request> 
	$B$O(B HTTP 1.0 $B$G5,Dj$5$l$k%j%/%(%9%H$G$9!#%j%/%(%9%HJ8;zNsCf!"!V(B\$B!W(B
	$B$O%(%9%1!<%WJ8;z$G$"$j!"<!$N$h$&$JCV$-49$($,9T$J$o$l$^$9!#(B

		\n	$B2~9T(B (0x0A)
		\r	$BI|5"(B (0x0D)
		\t	$B%?%V(B (0x09)
		\\	\    (0x5C)
		\a	$B@\B385$N(B IP $B%"%I%l%9(B
		\A	$B!V@\B385$N(B IP $B%"%I%l%9!W(B:$B!V%]!<%HHV9f!W(B
		\0	SSL $B>ZL@=q$N%7%j%"%kHV9f(B
		\1$B!A(B\9	SSL $B%*%W%7%g%s$N(B re<n>= $B$G;XDj$7$?@55,I=8=Cf!"(B
			( ... ) $BFb$N@55,I=8=$K%^%C%A$7$?J8;zNs(B

	(6) $B$O!"(Bhttp $B%j%/%(%9%H%X%C%@$N@hF,$K(B <header> $B$rDI2C$7$FCf7Q$7(B
	$B$^$9!#(B(5) $B$HF1MM$N%(%9%1!<%W$r;H$&$3$H$,$G$-$^$9!#(B

	(7) $B$O!"(Bstone $B$,@5>o$KF0:n$7$F$$$k$+8!::$9$k$?$a$N%]!<%H$N;XDj$G(B
	$B$9!#(B<sport> $B$G;XDj$7$?%]!<%H$K@\B3$7$F0J2<$N%3%^%s%I$rAw?.$9$k$H!"(B
	stone $B$N>uBV$,JV$5$l$^$9!#(B

		HELO $BG$0U$NJ8;zNs(B	stone $B$N>uBV$N0lMw$rJV$9(B
		LIMIT <var> <n>		$BJQ?t(B <var> $B$NCM$,(B <n> $BL$K~$+D4$Y$k(B

	<var> $B$O<!$N$&$A$N$$$:$l$+$G$9!#(B

		PAIR		pair $B$N8D?t(B
		CONN		conn $B$N8D?t(B
		ESTABLISHED	$B:G8e$K@\B33NN)$7$F$+$i$NIC?t(B
		READWRITE	$B:G8e$K(B read or write $B$7$F$+$i$NIC?t(B
		ASYNC		$B%9%l%C%I$NK\?t(B

	stone $B$+$i$N1~Ez$O!"@5>o;~$O(B 200 $BHVBf!"0[>o;~$O(B 500 $BHVBf$N?tCM$,(B
	$B@hF,$K$D$-$^$9!#(B

	<xhost> $B$rNs5s$9$k$3$H$K$h$j!"(Bstone $B$X@\B32DG=$J%^%7%s$r@)8B$9$k(B
	$B$3$H$,$G$-$^$9!#%^%7%sL>!"$"$k$$$O$=$N(B IP $B%"%I%l%9$r6uGr$G6h@Z$C(B
	$B$F;XDj$9$k$H!"$=$N%^%7%s$+$i$N@\B3$N$_$rCf7Q$7$^$9!#(B

	<xhost> $B$K!V(B/<mask>$B!W$rIU$1$k$H!"FCDj$N%M%C%H%o!<%/$N%^%7%s$+$i(B
	$B$N@\B3$r5v2D$9$k$3$H$,$G$-$^$9!#Nc$($P!"%/%i%9(B C $B$N%M%C%H%o!<%/(B 
	192.168.1.0 $B$N>l9g$O!"!V(B192.168.1.0/255.255.255.0$B!W$H;XDj$7$^$9!#(B
	$B!V(B192.168.1.0/24$B!W$J$I$H%S%C%H?t$G;XDj$9$k$3$H$b$G$-$^$9!#(B

	<xhost> $B$NBe$o$j$K!V(B!$B!W$r;XDj$9$k$H!"8eB3$N(B <xhost> $B$O@\B3$r5qH](B
	$B$9$k%^%7%s$N;XDj$K$J$j$^$9!#(B

	<sport> $B$K!V(B/udp$B!W$rIU$1$k$H!"(BTCP $B%Q%1%C%H$rCf7Q$9$kBe$o$j$K!"(B
	UDP $B%Q%1%C%H$rCf7Q$7$^$9!#(B

	<port> $B$K!V(B/apop$B!W$rIU$1$k$H!"(BPOP $B$r(B APOP $B$XJQ49$7$FCf7Q$7$^$9!#(B
	$BJQ49$K$O(B RSA Data Security $B<R$N(B MD5 Message-Digest $B%"%k%4%j%:%`(B
	$B$r;HMQ$7$^$9!#(B

	<port> $B$K!V(B/ssl$B!W$rIU$1$k$H!"%Q%1%C%H$r(B SSL $B$G0E9f2=$7$FCf7Q$7$^$9!#(B

	<sport> $B$K!V(B/ssl$B!W$rIU$1$k$H!"(BSSL $B$G0E9f2=$5$l$?%Q%1%C%H$rI|9f$7(B
	$B$FCf7Q$7$^$9!#(B

	<port> $B$K!V(B/base$B!W$rIU$1$k$H!"%Q%1%C%H$r(B MIME base64 $B$GId9f2=$7(B
	$B$FCf7Q$7$^$9!#(B

	<sport> $B$K!V(B/base$B!W$rIU$1$k$H!"(BMIME base64 $B$GId9f2=$5$l$?%Q%1%C(B
	$B%H$rI|9f$7$FCf7Q$7$^$9!#(B

	<sport> $B$K!V(B/http$B!W$rIU$1$k$H!"(Bhttp $B%j%/%(%9%H>e$N%Q%1%C%H$rCf7Q(B
	$B$7$^$9!#(B

$B;HMQJ}K!(B (NT $B%5!<%S%9HG(B)

	stone -install		stone $B%5!<%S%9$r%$%s%9%H!<%k$7$^$9!#(B
	stone -remove		stone $B%5!<%S%9$r:o=|$7$^$9!#(B
	stone -debug <params>	stone $B$r%"%W%j$H$7$F5/F0$7$^$9!#(B

	stone $B$K$O<+F0E*$K!V(B-C stone.cfg$B!W$,;XDj$5$l$^$9!#$9$J$o$A!"(B
	stone.exe $B$HF1$8%G%#%l%/%H%j$K$"$k@_Dj%U%!%$%k(B stone.cfg $B$K;XDj(B
	$B$5$l$?%*%W%7%g%s$,FI$_9~$^$l$^$9!#(B


$BNc(B
	outer: $B%U%!%$%"%&%)!<%k$N30B&$K$"$k%^%7%s(B
	inner: $B%U%!%$%"%&%)!<%k$NFbB&$K$"$k%^%7%s(B
	fwall: $B%U%!%$%"%&%)!<%k(B. $B$3$N%^%7%s>e$G(B stone $B$r<B9T(B

	stone 7 outer
		DISPLAY $B$G;XDj$7$?(B X server $B$X(B X $B%W%m%H%3%k$rCf7Q(B
		outer $B$G(B DISPLAY=inner:7 $B$H@_Dj$7$F(B X $B%/%i%$%"%s%H$r<B9T(B

	stone outer:telnet 10023
		outer $B$X(B telnet $B%W%m%H%3%k$rCf7Q(B
		inner $B$G(B telnet fwall 10023 $B$r<B9T(B

	stone outer:domain/udp domain/udp
		DNS $BLd$$9g$o$;$r(B outer $B$XCf7Q(B
		inner $B$G(B nslookup - fwall $B$r<B9T(B

	stone outer:ntp/udp ntp/udp
		outer $B$X(B NTP $B$rCf7Q(B
		inner $B$G(B ntpdate fwall $B$r<B9T(B

	stone localhost:http 443/ssl
		WWW $B%5!<%P$r(B https $BBP1~$K$9$k(B
		WWW $B%V%i%&%6$G(B https://fwall/ $B$r%"%/%;%9(B

	    $BCm0U(B: $BM"=PHG(B Netscape Navigator $BEy!"B?$/$N(B WWW $B%V%i%&%6$O(B 
		  512bit $BD6$N80$r07$($^$;$s(B

	stone localhost:telnet 10023/ssl
		telnet $B$r(B SSL $B2=(B
		inner $B$G(B SSLtelnet -z ssl fwall 10023 $B$r<B9T(B

	stone proxy 8080
		http proxy

	stone outer:pop/apop pop
		APOP $B$KBP1~$7$F$$$J$$%a!<%i$G(B inner:pop $B$X@\B3(B

	fwall $B$,(B http proxy (port 8080) $B$G$"$k;~(B:

	stone fwall:8080/http 10023 'POST http://outer:8023 HTTP/1.0'
	stone localhost:telnet 8023/http
		inner $B$H(B outer $B$G$=$l$>$l(B stone $B$r<B9T(B
		http $B>e$G%Q%1%C%H$rCf7Q(B

	stone fwall:8080/proxy 9080 'Proxy-Authorization: Basic c2VuZ29rdTpoaXJvYWtp'
		proxy $BG'>Z$KBP1~$7$F$$$J$$%V%i%&%6MQ(B


$B%[!<%`%Z!<%8(B

	stone $B$N8x<0%[!<%`%Z!<%8$O<!$N(B URL $B$G$9!#(B
	http://www.gcd.org/sengoku/stone/Welcome.ja.html


$BCx:n8"(B

	$B$3$N(B stone $B$K4X$9$kA4$F$NCx:n8"$O!"86Cx:n<T$G$"$k@g@P9@L@$,=jM-(B
	$B$7$^$9!#$3$N(B stone $B$O!"(BGNU General Public License (GPL) $B$K=`$:$k(B
	$B%U%j!<%=%U%H%&%'%"$G$9!#8D?ME*$K;HMQ$9$k>l9g$O!"2~JQ!&J#@=$K@)8B(B
	$B$O$"$j$^$;$s!#G[I[$9$k>l9g$O(B GPL $B$K=>$C$F2<$5$$!#$^$?!"(Bopenssl 
	$B$H%j%s%/$7$F;HMQ$9$k$3$H$r5v2D$7$^$9!#(B


$BL5J]>Z(B

	$B$3$N(B stone $B$OL5J]>Z$G$9!#$3$N(B stone $B$r;H$C$F@8$8$?$$$+$J$kB;32$K(B
	$BBP$7$F$b!"86Cx:n<T$O@UG$$rIi$$$^$;$s!#>\$7$/$O(B GPL $B$r;2>H$7$F2<(B
	$B$5$$!#(B


#2939								$B@g@P(B $B9@L@(B
http://www.gcd.org/sengoku/		Hiroaki Sengoku <sengoku@gcd.org>
