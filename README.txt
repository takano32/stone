
			    Simple Repeater

			   stone version 2.3e

		Copyright(c)1995-2008 by Hiroaki Sengoku
			    sengoku@gcd.org


  stone $B$O!"%"%W%j%1!<%7%g%s%l%Y%k$N(B TCP & UDP $B%j%T!<%?!<$G$9!#%U%!%$%"(B
$B%&%)!<%k$NFb$+$i30$X!"$"$k$$$O30$+$iFb$X!"(BTCP $B$"$k$$$O(B UDP $B$rCf7Q$7$^$9!#(B

  stone $B$K$O0J2<$N$h$&$JFCD'$,$"$j$^$9!#(B

1. Win32 $B$KBP1~$7$F$$$k(B
	$B0JA0$O(B UNIX $B%^%7%s$G9=@.$5$l$k$3$H$,B?$+$C$?%U%!%$%"%&%)!<%k$G$9(B
	$B$,!":G6a$O(B WindowsNT $B$,;H$o$l$k%1!<%9$,A}$($F$-$^$7$?!#(Bstone $B$O(B 
	WindowsNT $B$"$k$$$O(B Windows95 $B>e$G<j7Z$K<B9T$9$k$3$H$,$G$-$^$9!#(B
	$B$b$A$m$s!"(BLinux, FreeBSD, BSD/OS, SunOS, Solaris, HP-UX $B$J$I$N(B 
	UNIX $B%^%7%s$G$b;H$&$3$H$,$G$-$^$9!#(B

2. $BC1=c(B
	$B$o$:$+(B 10000 $B9T(B (C $B8@8l(B) $B$G$9$N$G!"%;%-%e%j%F%#%[!<%k$,@8$8$k2DG=(B
	$B@-$r:G>.8B$K$G$-$^$9!#(B

3. SSL $BBP1~(B
	OpenSSL (http://www.openssl.org/) $B$r;H$&$3$H$K$h$j!"0E9f2=(B/$BI|9f(B
	$B$7$FCf7Q$G$-$^$9!#$^$?!"%/%i%$%"%s%HG'>Z$*$h$S%5!<%PG'>Z$r%5%]!<(B
	$B%H$7$F$$$^$9!#$5$i$K!"G'>Z$K$h$C$FF@$i$l$k>ZL@=q$N%5%V%8%'%/%H$N(B
	$B0lIt$r!"Cf7Q@h$XAw$k$3$H$b$G$-$^$9!#(B

4. http proxy
	$B4J0W7?(B http proxy $B$H$7$F$b;H$&$3$H$,$G$-$^$9!#(B

5. POP -> APOP $BJQ49(B
	APOP $B$KBP1~$7$F$$$J$$%a!<%i$H(B stone $B$r;H$&$3$H$G!"(BAPOP $B%5!<%P$X(B
	$B%"%/%;%9$G$-$^$9!#(B

6. IPv6 $BBP1~(B
	IP/IPv6 $BJQ49$7$FCf7Q$9$k$3$H$,$G$-$^$9!#(BIPv6 $B$KBP1~$7$F$$$J$$(B
	$B%=%U%H%&%'%"$r<j7Z$K(B IPv6 $B2=$9$k$3$H$,2DG=$G$9!#(B


$B;HMQJ}K!(B

	stone [-C <file>] [-P <command>] [-Q <options>] [-N] [-d] [-p] [-n]
	      [-u <max>] [-f <n>] [-l] [-L <file>] [-a <file>] [-i <file>]
	      [-X <n>] [-T <n>] [-A <n>] [-r]
	      [-x <port>[,<port>][-<port>]... <xhost>... --]
	      [-s <send> <expect>... --]
	      [-b [<var>=<val>]... <n> <master>:<port> <backup>:<port>]
	      [-B <host>:<port> <host1>:<port1>... --]
	      [-I <host>]
	      [-o <n>] [-g <n>] [-t <dir>] [-D] [-c <dir>]
	      [-q <SSL>] [-z <SSL>]
	      [-M install <name>] [-M remove <name>]
	      <st> [-- <st>]...

	-C $B$O%*%W%7%g%s$*$h$S(B <st> $B$r%3%^%s%I%i%$%s$G;XDj$9$k$+$o$j$K@_(B
	$BDj%U%!%$%k$+$iFI$_9~$_$^$9!#(B-P $B$O@_Dj%U%!%$%k$rFI$_9~$`:]$N%W%j(B
	$B%W%m%;%C%5$r;XDj$7$^$9!#%W%j%W%m%;%C%5$XM?$($k0z?t$O(B -Q $B$G;XDj$G(B
	$B$-$^$9!#(B-N $B$r;XDj$9$k$H!"%3%^%s%I%i%$%s$*$h$S@_Dj%U%!%$%k$rFI$_(B
	$B9~$s$@8e!"=*N;$7$^$9!#$D$^$j%]!<%H$r3+$/$3$HL5$/@_Dj%U%!%$%k$N(B
	$B%A%'%C%/$r9T$J$&$3$H$,$G$-$^$9!#(B

	$B%*%W%7%g%s$H$7$F(B -d $B$r;XDj$9$k$H!"%G%P%C%0%l%Y%k$rA}2C$5$;$^$9!#(B 
	-p $B$r;XDj$9$k$HCf7Q$7$?%G!<%?$r%@%s%W$7$^$9!#(B-n $B$r;XDj$9$k$H!"%[(B
	$B%9%HL>$d%5!<%S%9L>$NBe$o$j$K(B IP $B%"%I%l%9$d%5!<%S%9HV9f$rI=<($7$^(B
	$B$9!#(B

	-u $B%*%W%7%g%s$OF1;~$K5-21$G$-$k(B UDP $B$NH/?.85$N:GBg?t$r;XDj$7$^$9!#(B
	$B%G%U%)%k%H$O(B 100 $B$G$9!#(B-f $B%*%W%7%g%s$O;R%W%m%;%9$N?t$r;XDj$7$^$9!#(B
	$B%G%U%)%k%H$O;R%W%m%;%9L5$7$G$9!#(B

	-l $B$r;XDj$9$k$H!"%(%i!<%a%C%;!<%8Ey$r(B syslog $B$X=PNO$7$^$9!#(B-L $B$r(B
	$B;XDj$9$k$H!"%(%i!<%a%C%;!<%8Ey$r(B file $B$X=PNO$7$^$9!#(B-a $B$r;XDj$9(B
	$B$k$H!"%"%/%;%9%m%0$r(B file $B$X=PNO$7$^$9!#(B-i $B$O(B stone $B$N%W%m%;%9(B 
	ID $B$r=PNO$9$k%U%!%$%k$r;XDj$7$^$9!#(B

	-X $B$OCf7Q$r9T$J$&:]$N%P%C%U%!$NBg$-$5$r;XDj$7$^$9!#%G%U%)%k%H$O(B
	1000 $B%P%$%H$G$9!#(B-T $B$r;XDj$9$k$H(B TCP $B%;%C%7%g%s$N%?%$%`%"%&%H$NIC(B
	$B?t$rJQ99$G$-$^$9!#%G%U%)%k%H$O(B 600 (10 $BJ,(B) $B$G$9!#(B-A $B$r;XDj$9$k$H(B
	listen $B8F$S=P$7$NL$=hM}@\B3%-%e!<$N:GBgD9$rJQ99$G$-$^$9!#%G%U%)%k(B
	$B%H$O(B 50 $B$G$9!#(B-r $B$r;XDj$9$k$H(B <st> $B$N%=%1%C%H$K(B SO_REUSEADDR $B$r@_(B
	$BDj$7$^$9!#(B

	-x $B$r;XDj$9$k$H(B http proxy $B$N@\B3@h$r@)8B$G$-$^$9!#@\B3@h$N%]!<(B
	$B%HHV9f$N%j%9%H(B <port>[,<port>][-<port>]... $B$*$h$S@\B3@h%[%9%H$N(B
	$B%j%9%H(B <xhost>... $B$r;XDj$7$^$9!#(B-x $B$rJ#?t;XDj$9$k$H!":G8e$K;XDj(B
	$B$7$?$b$N$+$i=g$K!"%]!<%HHV9f$N%j%9%H$,%^%C%A$9$k$b$N$r8!:w$7$^$9!#(B
	-x -- $B$r;XDj$9$k$H!"$=$l0JA0$N$b$N$O8!:wBP>]$H$J$j$^$;$s!#(B

	-b $B$OCf7Q@h(B <master>:<port> $B$K@\B3$G$-$J$$$H$-$N%P%C%/%"%C%W$H$7(B
	$B$F(B <backup>:<port> $B$r;XDj$7$^$9!#$9$J$o$A(B <n> $BIC$4$H$K(B 
	<master>:<port> $B$KBP$9$k%X%k%9%A%'%C%/(B ($B8e=R$9$k(B -s $B%*%W%7%g%s$G(B
	$B@_Dj(B) $B$,@.8y$9$k$+%A%'%C%/$7!"$b$7%A%'%C%/$K<:GT$7$?>l9g$O!"Cf7Q(B
	$B@h$r(B <backup>:<port> $B$XJQ99$7$^$9!#(B<var> $B$H$7$F!V(Bhost$B!W$r;XDj$9(B
	$B$k$3$H$K$h$j!"(B<master> $B$H$O0[$J$k%[%9%H$r%A%'%C%/$9$k$3$H$,$G$-(B
	$B$^$9!#F1MM$K!"(B<var> $B$H$7$F!V(Bport$B!W$r;XDj$9$k$3$H$K$h$j!"0[$J$k%]!<(B
	$B%H$r%A%'%C%/$9$k$3$H$,$G$-$^$9!#(B

	-s $B$O%X%k%9%A%'%C%/$N%9%/%j%W%H$r@_Dj$7$^$9!#(B<send> $B$rAw?.8e!"%l(B
	$B%9%]%s%9$,!"@55,I=8=(B <expect> $B$K%^%C%A$9$k$+3NG'$7$^$9!#(B

	-B $B$OCf7Q@h%0%k!<%W$N;XDj$G$9!#Cf7Q@h$,(B <host>:<port> $B$G$"$k>l9g!"(B
	$B$3$N%0%k!<%W$NCf$+$i%i%s%@%`$K0l$D$NCf7Q@h$rA*$s$GCf7Q$7$^$9!#(B-b 
	$B%*%W%7%g%s$G@_Dj:Q$_$NCf7Q@h$G!"%X%k%9%A%'%C%/$K<:GT$7$?$b$N$O!"(B
	$BA*Br;^$+$i=|30$7$^$9!#(B

	-I $B$OCf7Q@h$X@\B3$9$k:]$KMQ$$$k%$%s%?%U%'!<%9$r;XDj$7$^$9!#(B

	-o $B$H(B -g $B$O$=$l$>$l%f!<%6(B ID $B$H%0%k!<%W(B ID $B$r;XDj$7$^$9!#(BID $B$O?t(B
	$B;z$N$_;XDj2DG=$G$9!#(B-t $B$r;XDj$9$k$H!"(Bdir $B$X(B chroot $B$7$^$9!#(B-D $B$r(B
	$B;XDj$9$k$H!"(Bstone $B$r%G!<%b%s$H$7$F5/F0$7$^$9!#(B-c $B$O%3%"%@%s%W$r(B
	$B9T$J$&%G%#%l%/%H%j$r;XDj$7$^$9!#(B

	-M $B$O(B stone $B$r(B NT $B%5!<%S%9$H$7$FEPO?(B/$B:o=|$9$k$?$a$N%*%W%7%g%s$G(B
	$B$9!#%5!<%S%9L>(B <name> $B$r;XDj$7$^$9!#%5!<%S%9$H$7$FEPO?$7$?8e!"(B
	net start <name> $B%3%^%s%I$r<B9T$7$F%5!<%S%9$r3+;O$5$;$F$/$@$5$$!#(B
	$BNc(B:
		C:\>stone -M install repeater -C C:\stone.cfg
		C:\>net start repeater

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
	crl_check	CRL $B$r%A%'%C%/$7$^$9!#(B
	crl_check_all	$B>ZL@=q%A%'!<%s$NA4$F$K$*$$$F(B CRL $B$r%A%'%C%/$7$^$9!#(B
	uniq		SSL $B@\B3Aj<j$N(B SSL $B>ZL@=q$N%7%j%"%kHV9f$,A02s$N(B
			$B@\B3$H0[$J$k>l9g!"@\B3$r5qH]$7$^$9!#(B
	re<n>=<regex>	SSL $B>ZL@=q$N%A%'!<%s$,K~$?$9$Y$-@55,I=8=$r;XDj$7$^$9!#(B
			<n> $B$O(B depth $B$G$9!#(Bre0 $B$,>ZL@=q$N%5%V%8%'%/%H!"(B
			re1 $B$,$=$NH/9T<T$r0UL#$7$^$9!#(B
			<n> $B$O(B 9 $B$^$G;XDj$G$-$^$9!#(B
			<n> $B$,Ii$NCM$N>l9g$O!"(Bre-1 $B$,(B root CA $B$G!"(B
			re-2 $B$,$=$N;R(B CA $B$r0UL#$7$^$9!#(B
	depth=<n>	SSL $B>ZL@=q%A%'!<%s$ND9$5$N:GBgCM$r;XDj$7$^$9!#(B
			$B%A%'!<%s$ND9$5$,$3$NCM$r1[$($k$HG'>Z$,<:GT$7$^$9!#(B
			<n> $B$N:GBgCM$O(B 9 $B$G$9!#(B
	tls1		$B%W%m%H%3%k$H$7$F(B TLSv1 $B$rMQ$$$^$9!#(B
	ssl3		$B%W%m%H%3%k$H$7$F(B SSLv3 $B$rMQ$$$^$9!#(B
	ssl2		$B%W%m%H%3%k$H$7$F(B SSLv2 $B$rMQ$$$^$9!#(B
	no_tls1		$B%W%m%H%3%k$NA*Br;^$+$i(B TLSv1 $B$r30$7$^$9!#(B
	no_ssl3		$B%W%m%H%3%k$NA*Br;^$+$i(B SSLv3 $B$r30$7$^$9!#(B
	no_ssl2		$B%W%m%H%3%k$NA*Br;^$+$i(B SSLv2 $B$r30$7$^$9!#(B
	sni		$B%5!<%PL>DLCN(B (Server Name Indication) $B$r9T$J$$$^$9!#(B
	servername=<str>	SNI $B$GDLCN$9$k%5!<%PL>$r;XDj$7$^$9!#(B
	bugs		SSL $B$N<BAu$K%P%0$,$"$k@\B3Aj<j$H$N@\B3$r2DG=$K$7$^$9!#(B
	serverpref	SSL $B%5!<%P$N;XDj$7$?0E9f$rMQ$$$^$9(B (SSLv2 $B$N$_(B)$B!#(B
	sid_ctx=<str>	SSL $B%;%C%7%g%s(B ID $B%3%s%F%-%9%H$r@_Dj$7$^$9!#(B
	passfile=<file>	$BHkL)80$N%Q%9%U%l!<%:$r3JG<$7$?%U%!%$%k$r;XDj$7$^$9!#(B
	passfilepat=<file>	$B%U%!%$%kL>$N%Q%?!<%s$r;XDj$7$^$9!#(B
	key=<file>	$B>ZL@=q$NHkL)80%U%!%$%k$r;XDj$7$^$9!#(B
	keypat=<file>		$B%U%!%$%kL>$N%Q%?!<%s$r;XDj$7$^$9!#(B
	cert=<file>	$B>ZL@=q%U%!%$%k$r;XDj$7$^$9!#(B
	certpat=<file>		$B%U%!%$%kL>$N%Q%?!<%s$r;XDj$7$^$9!#(B
	certkey=<file>	$BHkL)80IU>ZL@=q%U%!%$%k$r;XDj$7$^$9!#(B
	certkeypat=<file>	$B%U%!%$%kL>$N%Q%?!<%s$r;XDj$7$^$9!#(B
	CAfile=<file>	$BG'>Z6I$N>ZL@=q%U%!%$%k$r;XDj$7$^$9!#(B
	CApath=<dir>	$BG'>Z6I$N>ZL@=q$,$"$k%G%#%l%/%H%j$r;XDj$7$^$9!#(B
	pfx=<file>	PKCS#12 $B%U%!%$%k$r;XDj$7$^$9!#(B
	pfxpat=<file>		$B%U%!%$%kL>$N%Q%?!<%s$r;XDj$7$^$9!#(B
	store=<prop>	[Windows] $B>ZL@=q%9%H%"Fb$NHkL)80IU>ZL@=q$r;XDj!#(B
			"SUBJ:<substr>" $B$"$k$$$O(B "THUMB:<hex>"
	storeCA		[Windows] $B>ZL@=q%9%H%"Fb$NG'>Z6I>ZL@=q$r;HMQ$7$^$9!#(B
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
	(3)	proxy <sport> [<xhost>...]
	(4)	<host>:<port>/http <sport> <request> [<xhost>...]
	(5)	<host>:<port>/proxy <sport> <header> [<xhost>...]
	(6)	health <sport> [<xhost>...]

	stone $B$r<B9T$7$F$$$k%^%7%s$N%]!<%H(B <sport> $B$X$N@\B3$r!"B>$N%^%7(B
	$B%s(B <host> $B$N%]!<%H(B <port> $B$XCf7Q$7$^$9!#%$%s%?%U%'!<%9$rJ#?t;}$D(B
	$B%^%7%s$G$O!"(B(2) $B$N$h$&$K%$%s%?%U%'!<%9$N%"%I%l%9(B <shost> $B$r;XDj(B
	$B$9$k$3$H$K$h$j!"FCDj$N%$%s%?%U%'!<%9$X$N@\B3$N$_$rE>Aw$9$k$3$H$,(B
	$B$G$-$^$9!#(B<host>:<port> $B$NBe$o$j$K!"!V(B/$B!W$J$$$7!V(B./$B!W$+$i;O$^$k(B
	$B%Q%9L>$r;XDj$9$k$3$H$K$h$j!"(BUNIX $B%I%a%$%s%=%1%C%H$r07$&$3$H$b$G(B
	$B$-$^$9!#(B

	(3) $B$O!"(Bhttp proxy $B$G$9!#(BWWW $B%V%i%&%6$N(B http proxy $B$N@_Dj$G!"(B
	stone $B$r<B9T$7$F$$$k%^%7%s$*$h$S%]!<%H(B <sport> $B$r;XDj$7$^$9!#(B
	$B!V(Bproxy$B!W$K$O!"!V(B/$B!W$KB3$1$F0J2<$N3HD%;R$rIU$1$k$3$H$,$G$-$^$9!#(B

	v4only	proxy $B$N@\B3@h$r(B IP $B%"%I%l%9$K8BDj$7$^$9!#(B

	v6only	proxy $B$N@\B3@h$r(B IPv6 $B%"%I%l%9$K8BDj$7$^$9!#(B

	(4) $B$O!"(Bhttp $B%j%/%(%9%H$K$N$;$FCf7Q$7$^$9!#(B<request> $B$O(B HTTP 1.0 
	$B$G5,Dj$5$l$k%j%/%(%9%H$G$9!#%j%/%(%9%HJ8;zNsCf!"!V(B\$B!W$O%(%9%1!<(B
	$B%WJ8;z$G$"$j!"<!$N$h$&$JCV$-49$($,9T$J$o$l$^$9!#(B

		\n	$B2~9T(B (0x0A)
		\r	$BI|5"(B (0x0D)
		\t	$B%?%V(B (0x09)
		\\	\    (0x5C)
		\a	$B@\B385$N(B IP $B%"%I%l%9(B
		\A	$B!V@\B385$N(B IP $B%"%I%l%9!W(B:$B!V%]!<%HHV9f!W(B
		\d	$B@\B3@h$N(B IP $B%"%I%l%9(B
		\D	$B!V@\B3@h$N(B IP $B%"%I%l%9!W(B:$B!V%]!<%HHV9f!W(B($BF)2a%W%m%-%7MQ(B)
		\u	$B@\B385$N%f!<%6(BID ($BHV9f(B)
		\U	$B@\B385$N%f!<%6L>(B
		\g	$B@\B385$N%0%k!<%W(BID ($BHV9f(B)
		\G	$B@\B385$N%0%k!<%WL>(B
			\u \U \g \G $B$O(B UNIX $B%I%a%$%s%=%1%C%H$N>l9g$N$_(B
		\0	SSL $B>ZL@=q$N%7%j%"%kHV9f(B
		\1 - \9	SSL $B%*%W%7%g%s$N(B re<n>= $B$G;XDj$7$?@55,I=8=Cf!"(B
			( ... ) $BFb$N@55,I=8=$K%^%C%A$7$?J8;zNs(B
		\?1<then>\:<else>\/
			$B$b$7(B \1 (\2 - \9 $B$bF1MM(B) $B$NJ8;zNs$,!"6uJ8;zNs$G(B
			$B$J$1$l$P(B <then>$B!"6uJ8;zNs$G$"$l$P(B <else>

	(5) $B$O!"(Bhttp $B%j%/%(%9%H%X%C%@$N@hF,$K(B <header> $B$rDI2C$7$FCf7Q$7(B
	$B$^$9!#(B(4) $B$HF1MM$N%(%9%1!<%W$r;H$&$3$H$,$G$-$^$9!#!V(B/proxy$B!W$NBe(B
	$B$o$j$K!V(B/mproxy$B!W$r;XDj$9$k$H!"%j%/%(%9%H%X%C%@$4$H$K(B <header> 
	$B$rDI2C$7$^$9!#(B

	(6) $B$O!"(Bstone $B$,@5>o$KF0:n$7$F$$$k$+8!::$9$k$?$a$N%]!<%H$N;XDj$G(B
	$B$9!#(B<sport> $B$G;XDj$7$?%]!<%H$K@\B3$7$F0J2<$N%3%^%s%I$rAw?.$9$k$H!"(B
	stone $B$N>uBV$,JV$5$l$^$9!#(B

		HELO $BG$0U$NJ8;zNs(B	stone, pair, trash $BEy$N8D?t(B
		STAT			$B%9%l%C%I$N8D?t(B, mutex $B%3%s%U%j%/%H2s?t(B
		FREE			free $B%j%9%HD9(B
		CLOCK			$B7P2aIC?t(B
		CVS_ID			CVS $B$N(B ID
		CONFIG			config $B%U%!%$%k$NFbMF(B
		STONE			$B3F(B stone $B$N@_DjFbMF(B
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

	<xhost> $B$K$O!"!V(B/$B!W$KB3$1$F0J2<$N3HD%;R$rIU$1$k$3$H$,$G$-$^$9!#(B
	$BJ#?t$N3HD%;R$r;XDj$9$k$H$-$O!V(B,$B!W$G6h@Z$j$^$9!#(B

	<m>	$B%M%C%H%o!<%/!&%^%9%/$N%S%C%H?t$r;XDj$9$k$3$H$K$h$j!"FCDj(B
		$B$N%M%C%H%o!<%/$N%^%7%s$+$i$N@\B3$r5v2D$9$k$3$H$,$G$-$^$9!#(B
		$BNc$($P!"%/%i%9(B C $B$N%M%C%H%o!<%/(B 192.168.1.0 $B$N>l9g$O!"(B
		$B!V(B192.168.1.0/24$B!W$H;XDj$7$^$9!#(B

	v4	<xhost> $B$r(B IP $B%"%I%l%9$H$7$F07$$$^$9!#(B

	v6	<xhost> $B$r(B IPv6 $B%"%I%l%9$H$7$F07$$$^$9!#(B

	p<m>	<xhost> $B$+$i$N@\B3$N$_!"Cf7Q$7$?%G!<%?$r%@%s%W$7$^$9!#(B
		<m> $B$O%@%s%WJ}K!$N;XDj$G$9!#(B-p $B%*%W%7%g%s$N8D?t$KAjEv$7(B
		$B$^$9!#(B

	<xhost> $B$NBe$o$j$K!V(B!$B!W$r;XDj$9$k$H!"8eB3$N(B <xhost> $B$O@\B3$r5qH](B
	$B$9$k%^%7%s$N;XDj$K$J$j$^$9!#(B

	<port> $B$K$O!"!V(B/$B!W$KB3$1$F0J2<$N3HD%;R$rIU$1$k$3$H$,$G$-$^$9!#(B
	$BJ#?t$N3HD%;R$r;XDj$9$k$H$-$O!V(B,$B!W$G6h@Z$j$^$9!#(B

	udp	TCP $B$rCf7Q$9$kBe$o$j$K!"(BUDP $B$rCf7Q$7$^$9!#(B

	ssl	SSL $B$G0E9f2=$7$FCf7Q$7$^$9!#(B

	v6	$BCf7Q@h$X(B IPv6 $B@\B3$7$^$9!#(B

	base	MIME base64 $B$GId9f2=$7$FCf7Q$7$^$9!#(B

	<sport> $B$K$O!"!V(B/$B!W$KB3$1$F0J2<$N3HD%;R$rIU$1$k$3$H$,$G$-$^$9!#(B
	$BJ#?t$N3HD%;R$r;XDj$9$k$H$-$O!V(B,$B!W$G6h@Z$j$^$9!#(B

	udp	TCP $B$rCf7Q$9$kBe$o$j$K!"(BUDP $B$rCf7Q$7$^$9!#(B

	apop	POP $B$r(B APOP $B$XJQ49$7$FCf7Q$7$^$9!#(B
		$BJQ49$K$O(B RSA Data Security $B<R$N(B MD5 Message-Digest $B%"%k(B
		$B%4%j%:%`$r;HMQ$7$^$9!#(B

	ssl	SSL $B$rI|9f$7$FCf7Q$7$^$9!#(B

	v6	IPv6 $B@\B3$r<uIU$1$^$9!#(B(1) $B$N$h$&$K%$%s%?%U%'!<%9$N(B
		$B%"%I%l%9(B <shost> $B$r;XDj$7$J$$>l9g$O!"(BIP $B@\B3$b<uIU$1$k$3(B
		$B$H$,$G$-$^$9!#(B

	v6only	IPv6 $B@\B3$N$_$r<uIU$1$^$9!#(B(1) $B$N$h$&$K%$%s%?%U%'!<%9$N(B
		$B%"%I%l%9(B <shost> $B$r;XDj$7$J$$>l9g$b!"(BIP $B@\B3$r<uIU$1$k$3(B
		$B$H$O$"$j$^$;$s!#(B

	base	MIME base64 $B$rI|9f$7$FCf7Q$7$^$9!#(B

	http	http $B%j%/%(%9%H%X%C%@$r<h$j=|$$$FCf7Q$7$^$9!#(B

	ident	$B@\B3$r<uIU$1$k$H$-$K@\B385$KBP$7(B ident $B%W%m%H%3%k(B 
		(RFC1413) $B$r;H$C$F%f!<%6L>$r>H2q$7$^$9!#(B


$BNc(B
	outer: $B%U%!%$%"%&%)!<%k$N30B&$K$"$k%^%7%s(B
	inner: $B%U%!%$%"%&%)!<%k$NFbB&$K$"$k%^%7%s(B
	fwall: $B%U%!%$%"%&%)!<%k(B. $B$3$N%^%7%s>e$G(B stone $B$r<B9T(B

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

	stone localhost:telnet 10023/ssl
		telnet $B$r(B SSL $B2=(B
		inner $B$G(B SSLtelnet -z ssl fwall 10023 $B$r<B9T(B

	stone proxy 8080
		http proxy

	stone outer:110/apop 110
		APOP $B$KBP1~$7$F$$$J$$%a!<%i$G(B inner:pop $B$X@\B3(B

	fwall $B$,(B http proxy (port 8080) $B$G$"$k;~(B:

	stone fwall:8080/http 10023 'POST http://outer:8023 HTTP/1.0'
	stone localhost:telnet 8023/http
		inner $B$H(B outer $B$G$=$l$>$l(B stone $B$r<B9T(B
		http $B%j%/%(%9%H$K$N$;$FCf7Q(B

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
