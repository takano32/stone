
			    Simple Repeater

			   stone version 2.2

		Copyright(c)1995-2003 by Hiroaki Sengoku
			    sengoku@gcd.org


  Stone is a TCP/IP packet repeater in the application layer.  It
repeats TCP and UDP packets from inside to outside of a firewall, or
from outside to inside.

  Stone has following features:

1.  Stone supports Win32.
	Formerly, UNIX machines are used as firewalls, but recently
	WindowsNT machines are used, too.  You can easily run Stone on
	WindowsNT and Windows95.  Of course, available on Linux,
	FreeBSD, BSD/OS, SunOS, Solaris, HP-UX and so on.

2.  Simple.
	Stone's source code is only 4000 lines long (written in C
	language), so you can minimize the risk of security
	holes.

3.  Stone supports SSL.
	Using OpenSSL (http://www.openssl.org/), stone can
	encrypt/decrypt packets.  Client verifications, and server
	verifications are also supported.  Stone can send a substring of
	the subject of the certificate to the destination.

4.  Stone is a http proxy.
	Stone can also be a tiny http proxy.

5.  POP -> APOP conversion.
	With stone and a mailer that does not support APOP, you can
	access to an APOP server.


HOWTO USE

	stone [-C <file>] [-P <command>] [-Q <options>] [-d] [-p] [-n]
	      [-u <max>] [-f <n>] [-l] [-L <file>] [-a <file>] [-i <file>]
	      [-X <n>] [-T <n>] [-o <n>] [-g <n>] [-t <dir>]
	      [-q <SSL>] [-z <SSL>] [-D]
	      <st> [-- <st>]...

	If the ``-C <file>'' flag is used, the program read these
	options and ``<st>''s from the configuration file ``<file>''.
	If the ``-P <command>'' flag is used, the program executes
	pre-processor to read the configuration file.  ``-Q <options>''
	can be used to pass options to the pre-processor.

	If the ``-d'' flag is used, then increase the debug level.  If
	the ``-p'' flag is used, data repeated by stone are dumped.  If
	the ``-n'' is used, IP addresses and service port numbers are
	shown instead of host names and service names.

	If the ``-u <max>'' flag (``<max>'' is integer) is used, the
	program memorize ``<max>'' sources simultaneously where UDP
	packets are sent.  If the ``-f <n>'' flag (``<n>'' is integer)
	is used, the program spawn ``<n>'' child processes.

	If the ``-l'' flag is used, the program sends error messages to
	the syslog instead of stderr.  If the ``-L <file>'' (``<file>''
	is a file name) flag is used, the program writes error messages
	to the file.  If the ``-a <file>'' flag is used, the program
	writes accounting to the file.  If the ``-i <file>'' flag is
	used, the program writes its process ID to the file.

	The ``-X <n>'' flag alters the buffer size of the repeater.  If
	the ``-T <n>'' is used, the timeout of TCP sessions can be
	specified to ``<n>'' sec.

	If the ``-o <n>'' or ``-g <n>'' flag is used, the program set
	its uid or gid to ``<n>'' respectively.  If the ``-t <dir>''
	flag (``<dir>'' is a directory) is used, the program change its
	root to the directory.

	The ``-q <SSL>'' and the ``-z <SSL>'' flags are for SSL
	encryption.  The ``-q <SSL>'' is for the client mode, that is,
	when stone connects to the other SSL server as a SSL client.
	The ``-z <SSL>'' if for the server mode, that is, when other SSL
	clients connect to the stone.

	``<SSL>'' is one of the following.

	default		reset SSL options to the default.
			Using multiple <st>, different SSL options can
			be designated for each <st>.
	verbose		verbose mode.
	verify		require SSL certificate to the peer.
	verify,once	request a client certificate on the initial TLS/SSL
			handshake. (-z only)
	verify,ifany	The certificate returned (if any) is checked. (-z only)
	verify,none	never request SSL certificate to the peer.
	re<n>=<regex>	designate a regular expression <regex>.
			The certificate of the peer must satisfy the
			regex.  <n> is the depth.  re0 means the subject
			of the certificate, and re1 means the issure.
			The maximum of <n> is 9.
	depth=<n>	The maximum of the certificate chain.
			If the peer's certificate exceeds <n>, the
			verification fails.  The maximum of <n> is 9.
	key=<file>	The filename of the secret key of the certificate.
	cert=<file>	The filename of the certificate.
	CAfile=<file>	The filename of the certificate of the CA.
	CApath=<dir>	The directory of the certificate files.
	cipher=<list>	The list of ciphers.

	``<st>'' is one of the following.  Multiple ``<st>'' can be
	designated, separated by ``--''.

	(1)	<host>:<port> <sport> [<xhost>...]
	(2)	<host>:<port> <shost>:<sport> [<xhost>...]
	(3)	<display> [<xhost>...]
	(4)	proxy <sport> [<xhost>...]
	(5)	<host>:<port>/http <request> [<hosts>...]
	(6)	<host>:<port>/proxy <header> [<hosts>...]

	The program repeats the connection on port ``<sport>'' to the
	other machine ``<host>'' port ``<port>''.  If the machine, on
	which the program runs, has two or more interfaces, type (2) can
	be used to repeat the connection on the specified interface
	``<shost>''.

	Type (3) is the abbreviating notation.  The program repeats the
	connection on display number ``<display>'' to the X server
	designated by the environment variable ``DISPLAY''.

	Type (4) is a http proxy.  Specify the machine, on which the
	program runs, and port ``<sport>'' in the http proxy settings of
	your WWW browser.

	Type (5) repeats packets over http request.  ``<request>'' is
	the request specified in HTTP 1.0.  In the ``<request>'', ``\''
	is the escape character, and the following substitution occurs.

		\n	newline  (0x0A)
		\r	return   (0x0D)
		\t	tab      (0x09)
		\\	\ itself (0x5C)
		\a	the IP address of the client connecting to the stone.
		\1 - \9	the matched string in the ``regex'' of SSL options.

	Type (6) repeats http request with ``<header>'' in the top of
	request headers.  The above escapes can be also used.

	If the ``<xhost>'' are used, only machines ``<xhost>'' can
	connect to the program.

	If the ``<xhost>/<mask>'' are used, only machines on specified
	networks are permitted to connect to the program.  In the case
	of class C network 192.168.1.0, for example, use
	``192.168.1.0/255.255.255.0''.

	If the ``<sport>/udp'' is used, repeats UDP packets instead of
	TCP packets.

	If the ``<sport>/apop'' is used, converts POP to APOP.  The
	conversion is derived from the RSA Data Security, Inc. MD5
	Message-Digest Algorithm.

	If the ``<port>/ssl'' is used, repeats packets with encryption.

	If the ``<sport>/ssl'' is used, repeats packets with decryption.

	If the ``<port>/base'' is used, repeats packets with MIME base64
	encoding.

	If the ``<sport>/base'' is used, repeats packets with MIME
	base64 decoding.

	If the ``<sport>/http'' is used, repeats packets over http.


EXAMPLES
	outer: a machine in the outside of the firewall
	inner: a machine in the inside of the firewall
	fwall: the firewall on which the stone is executed

	stone 7 outer
		Repeats the X protocol to the machine designated by the
		environmental variable ``DISPLAY''.  Run X clients under
		``DISPLAY=inner:7'' on ``outer''.

	stone outer:telnet 10023
		Repeats the telnet protocol to ``outer''.
		Run ``telnet fwall 10023'' on ``inner''.

	stone outer:domain/udp domain/udp
		Repeats the DNS query to ``outer''.
		Run ``nslookup - fwall'' on ``inner''.

	stone outer:ntp/udp ntp/udp
		Repeats the NTP to ``outer''.
		Run ``ntpdate fwall'' on ``inner''.

	stone localhost:http 443/ssl
		Make WWW server that supports ``https''.
		Access ``https://fwall/'' using a WWW browser.

	    NOTICE: Most WWW browsers, such as the export versions of
		    Netscape Navigator, can't handle keys whose length
		    are longer than 512 bit.

	stone localhost:telnet 10023/ssl
		Make telnet server that supports SSL.
		Run ``SSLtelnet -z ssl fwall 10023'' on ``inner''.

	stone proxy 8080
		http proxy.

	stone outer:pop/apop pop
		connect to inner:pop using a mailer that does not
		support APOP.

	Where fwall is a http proxy (port 8080):

	stone fwall:8080/http 10023 'POST http://outer:8023 HTTP/1.0'
	stone localhost:telnet 8023/http
		Run stones on ``inner'' and ``outer'' respectively.
		Repeats packets over http.

	stone fwall:8080/proxy 9080 'Proxy-Authorization: Basic c2VuZ29rdTpoaXJvYWtp'
		for browser that does not support proxy authorization.


HOMEPAGE

	The official homepage of stone is:
	http://www.gcd.org/sengoku/stone/


COPYRIGHT

	All rights about this program ``stone'' are reserved by the
	original author, Hiroaki Sengoku.  The program is free software;
	you can redistribute it and/or modify it under the terms of the
	GNU General Public License (GPL).  Furthermore you can link it
	with openssl.


NO WARRANTY

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY.


#2939
http://www.gcd.org/sengoku/		Hiroaki Sengoku <sengoku@gcd.org>
