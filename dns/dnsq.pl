#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Std;
use POSIX;
use Socket;
use Net::DNS::Packet;
our ($opt_v, $opt_r, $opt_c, $opt_a, $opt_d);
getopts('vr:c:ad') || &help;
my $Verbose = $opt_v;
my $Debug = $opt_d;
my $MinSleep = 0.001;
my $CacheFile = $opt_c;
my @RootServers = qw(
198.41.0.4	192.228.79.201	192.33.4.12	128.8.10.90
192.203.230.10	192.5.5.241	192.112.36.4	128.63.2.53
192.36.148.17	192.58.128.30	193.0.14.129	198.32.64.12
202.12.27.33
);
my %Query;
my %Answer;
my %Answer2;
my %AnswerNS;
my $NAnswers = 0;
my $NAnswersMax;
my %Authority;
if (defined $CacheFile) {
    dbmopen(%Authority, $CacheFile, 0644) || die;
}

END {
    if (defined $CacheFile) {
	dbmclose(%Authority);
    }
}

my @QueryStack;
my %QueryIDs;
my $now = time;
my $nowstr = &now;
srand($now ^ $$);
my $proto = getprotobyname('udp');
my $DNS_Port = getservbyname('domain', 'udp');
socket(SOCKET, PF_INET, SOCK_DGRAM, $proto) || die;
bind(SOCKET, sockaddr_in(0, INADDR_ANY)) || die;
my $mysockaddr = getsockname(SOCKET);
my ($myport, $myaddr) = sockaddr_in($mysockaddr);
printf("%s my socket: %s:%d\n",
       $nowstr, inet_ntoa($myaddr), $myport) if $Verbose;

while (<>) {
    if (/^\s*(\S*\.[A-Z]+)\s*$/i) {
	unshift @QueryStack, uc($1) . "\n";
    }
}
if (defined $opt_r && 0 < $opt_r && $opt_r <= 100) {
    $NAnswersMax = ceil(@QueryStack * $opt_r / 100);
} else {
    $NAnswersMax = (scalar @QueryStack);
}
my $sleep = $MinSleep;
while ($NAnswers < $NAnswersMax) {
    my $busy = 0;
    $now = time;
    $nowstr = &now;
    $_ = pop(@QueryStack);
    if (defined $_ && /\n/) {
	@_ = split(/\n/);
	my ($name, $ip, @rest) = @_;
	my $rest = "";
	if (defined $ip && $ip) {
	    if (@rest > 0) {
		$rest = join("\n", @rest) . "\n";
	    }
	    sendquery($name, $ip, $rest);
	} elsif ($name =~ /\.[A-Z]+$/) {
	    $Query{$name} = $now if $name !~ /[\/\\\@]/;
	    print "$nowstr $name query start\n" if $Verbose;
	    ($ip, @rest) = split(/\n/, authority($name));
	    if (@rest > 0) {
		$rest = "$name\n" . join("\n$name\n", @rest) . "\n";
	    }
	    sendquery($name, $ip, $rest);
	} else {
	    print STDERR "$nowstr Irregular job on stack: $_\n" if $Verbose;
	}
	$busy++;
    }
    my $resdata;
    my $fromsockaddr = recv(SOCKET, $resdata, 512, MSG_DONTWAIT);
    if (defined($fromsockaddr)) {
	my ($fromport, $fromaddr) = sockaddr_in($fromsockaddr);
	my $respacket = Net::DNS::Packet->new(\$resdata);
	if (defined($respacket)) {
	    parseres($respacket, inet_ntoa($fromaddr));
	    $busy++;
	} else {
	    printf("%s null packet from %s:%d ignored\n",
		   $nowstr, inet_ntoa($fromaddr), $fromport) if $Verbose;
	}
    }
    if ($busy) {
	$sleep = $MinSleep;
    } else {
	my $n = 0;
	for (keys %QueryIDs) {
	    if ($QueryIDs{$_} =~ /^.+\n(\d+)\n/ && $now - $1 > 10) {
		my $rest = $';	#';
		delete $QueryIDs{$_};
		unshift @QueryStack, $rest if $rest;
	    } else {
		$n++;
	    }
	}
	if ($sleep > 1) {
	    my $m = (scalar @QueryStack);
	    my $q = (scalar keys %Query);
	    printf("%s #QueryStack=%d #QueryIDs=%d #Query=%d\n",
		   $nowstr, $m, $n, $q) if $Verbose;
	    last if $n == 0 && $m == 0;
	}
	sleep $sleep;
	$sleep *= 2 if $sleep < 2;
    }
}
if ($opt_a) {
    for (keys %Authority) {
	print "\n$_\n", $Authority{$_};
    }
    print "\n";
    for (keys %Answer2) {
	print "$_ ", $Answer2{$_}, "\n";
    }
}

sub sendquery {
    my ($name, $ip, $rest) = @_;
    print "$nowstr name=$name, ip=$ip, rest=$rest\n---\n" if $Debug;
    my $q = $name;
    $q =~ s/[\/\\\@].*//;
    return if defined $Answer{$q};
    my $id = floor(rand(65536));
    my $domain;
    if ($ip =~ /\@/) {
	$ip = $`;
	$domain = $';	#';
    }
    if ($name =~ /\@([^\/\\\@]+)$/) {
	$q = $`;
    } else {
	$q = $name;
	$name .= "\@$domain" if defined $domain;
    }
    $q =~ s/.*[\/\\]//;
    return if defined $Answer2{$q};
    my $querypacket = Net::DNS::Packet->new($q, "A", "IN");
    my $header = $querypacket->header;
    $header->rd(0);
    $header->id($id);
    my $querydata = $querypacket->data;
    my $sockaddr = sockaddr_in($DNS_Port, inet_aton($ip));
    my $ret = send(SOCKET, $querydata, 0, $sockaddr);
    printf("%s %s sent to: %s:%d ID=%d\n",
	   $nowstr, $name, $ip, $DNS_Port, $id) if $Verbose;
    $QueryIDs{"$ip\n$id"} = "$name\n$now\n$rest";
}

sub parseres {
    my ($packet, $ip) = @_;
    my $id = $packet->header->id;
    printf("%s received from: %s ID=%d\n", $nowstr, $ip, $id) if $Verbose;
    my $name = $QueryIDs{"$ip\n$id"};
    if (! defined $name || $name !~ /^(.+)\n/) {
	print STDERR "$nowstr Irregular packet from $ip dropped (ID=$id)\n"
	    if $Verbose;
	return;
    }
    $name = $1;
    my $rest = $';	#';
    delete $QueryIDs{"$ip\n$id"};
    my $domain;
    if ($name =~ /\@([^\/\\\@]+)$/) {
	$domain = $1;
	$name = $`;
    }
    my $top;
    my $sep;
    my $mid;
    my $upp;	# top + mid
    my $bot;
    if ($name =~ /([\/\\\@])/) {
	$top = $`;
	$sep = $1;
	$bot = $';	#';
	if ($bot =~ /(.*)\//) {
	    $mid = "$sep$1";
	    $upp = "$top$mid";
	    $sep = "/";
	    $bot = $';	#';
	} else {
	    $upp = $top;
	}
	return if defined $Answer2{$bot};
    } else {
	$top = $name;
    }
    return if defined $Answer{$top};
    my @additional = $packet->additional;
    my %additional;
    for my $rr (@additional) {
	if ($rr->type eq "A" and $rr->class eq "IN") {
	    printf("%s %s\n", $nowstr, $rr->string) if $Verbose;
	    my $additional = uc($rr->name);
	    my $data = $rr->rdatastr;
	    $additional{$additional} = $data;
#	    printf("%s %s additional: name=%s data=%s\n",
#		   $nowstr, $name, $additional, $data) if $Verbose;
	    if (defined $sep) {
		if ($additional eq $bot) {
		    if ($sep eq "/") {
			if ($upp =~ /\@([^\/\\\@]+)$/) {
			    addAuthority($1, $data);
			}
			push @QueryStack, "$upp\n$data\n";
			$Answer2{$bot} = $data;
		    } else {
			finish($top, $data);
		    }
		    return;
		}
	    } else {
		if ($additional eq $top) {
		    finish($top, $data);
		    return;
		}
	    }
	}
    }
    my @answer = $packet->answer;
    if (@answer > 0) {
	my $job;
	for my $rr (@answer) {
	    my $data = uc($rr->rdatastr);
	    $data =~ s/\.$//;
	    printf("%s %s\n", $nowstr, $rr->string) if $Verbose;
	    if (loopcheck($name, $data)) {
		print "$nowstr $name loop detected: $data\n";
		next;
	    }
	    if ($rr->type eq "A") {
		if (defined $sep && $sep eq "/") {
		    if ($upp =~ /\@([^\/\\\@]+)$/) {
			$upp = $`;
			addAuthority($1, $data);
			$Answer2{$bot} = $data;
		    }
		    $job .= "$upp\n" . $rr->rdatastr . "\n";
		    next;
		}
		finish($top, $rr->rdatastr);
		return;
	    }
	    if ($rr->type eq "CNAME") {
		my $data = uc($rr->rdatastr);
		$data =~ s/\.$//;
		if (defined $sep) {
		    $job .= "$upp$sep$data\n\n";
		} else {
		    $job .= "$top\\$data\n\n";
		}
		next;
	    }
	    print "$nowstr $name unknown response (ID=$id):\n";
	    $packet->print;
	    print "\n";
	}
	push @QueryStack, $job if defined $job;
	return;
    }
    my @authority = $packet->authority;
    if (@authority > 0) {
	my $job;
	my $job2;
	for my $rr (@authority) {
	    my $dom = uc($rr->name);
	    $dom .= "." if $dom !~ /\.$/;
	    if (defined $domain && !subdomain($domain, $dom)) {
		print STDERR
		    "$nowstr $domain Irregular authority $dom ignored\n";
		next;
	    }
	    printf("%s %s\n", $nowstr, $rr->string) if $Verbose;
	    my $data = uc($rr->rdatastr);
	    $data =~ s/\.$//;
	    if (defined($additional{$data})) {
		addAuthority($dom, $additional{$data});
		$job .= "$name\@$dom\n" . $additional{$data} . "\n";
	    } elsif (loopcheck($name, $data)) {
		print "$nowstr $name loop detected: $data\n";
	    } elsif ($rr->type eq "NS") {
		$job2 .= "$name\@$dom/$data\n\n";
	    } elsif ($rr->type eq "SOA") {
	    } else {
		print "$nowstr $name unknown record (ID=$id):\n";
		$rr->print;
		print "\n";
	    }
	}
	if (defined $job) {
	    push @QueryStack, $job;
	    return;
	} elsif (defined $job2) {
	    push @QueryStack, $job2;
	    return;
	}
    }
    print "$nowstr $name no record\n" if $Verbose;
    if ($rest =~ /^\d+\n/) {
	push @QueryStack, $';	#';
    }
}

sub finish {
    my ($name, $ip) = @_;
    $Answer{$name} = $ip;
    $NAnswers++;
    if ($Verbose) {
	my $time = $now - $Query{$name};
	printf("%s answer %d %s %s\n", $nowstr, $time, $name, $ip);
    } else {
	printf("%s %s\n", $name, $ip);
    }
    delete $Query{$name} if defined $Query{$name};
}

sub loopcheck {
    my ($name, $data) = @_;
    my $pos = index($name, $data);
    if ($pos >= 0) {
	my $c;
	if ($pos == 0) {
	    $c = "/";
	} else {
	    $c = substr($name, $pos-1, 1);
	}
	if ($c eq "/" || $c eq "\\" || $c eq "\@") {
	    $pos += length($data);
	    my $len = length($name);
	    if ($pos == $len) {
		$c = "/";
	    } else {
		$c = substr($name, $pos, 1);
	    }
	    if ($c eq "/" || $c eq "\\" || $c eq "\@") {
		return 1;	# loop detected
	    }
	}
    }
    return 0;
}

sub subdomain {
    my ($dom, $sub) = @_;
    $dom = ".$dom" if $dom !~ /^\./;
    my $length = length($dom);
    substr($sub, -$length) eq $dom;
}

sub addAuthority {
    my ($dom, $ip) = @_;
    $dom = uc($dom);
    $dom .= "." if $dom !~ /\.$/;
    if (defined($Authority{$dom})) {
	my $pos = index($Authority{$dom}, "$ip\n");
	if ($pos == 0 || substr($Authority{$dom}, $pos-1, 1) eq "\n") {
	    return;
	}
    }
    $Authority{$dom} .= "$ip\@$dom\n";
    printf("%s authority %s %s\n", $nowstr, $dom, $ip) if $Verbose;
}

sub authority {
    my ($name) = @_;
    my $dom = uc($name);
    if ($dom =~ /.*[\/\\]/) {
	$dom = $';	#';
    }
    $dom .= "." if $dom !~ /\.$/;
    while ($dom) {
	$dom =~ s/^[^\.]+\.//;
	if (defined $Authority{$dom}) {
	    print "$nowstr $name use authority: $dom\n" if $Verbose;
	    return $Authority{$dom};
	}
    }
    my $n = (scalar @RootServers);
    my $j = floor(rand($n));
    my $ret = "";
    for (my $i=0; $i < 3; $i++, $j++) {
	$ret .= $RootServers[$j % $n] . "\@.\n";
    }
    return $ret;
}

sub now {
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($now);
    sprintf("%02d:%02d:%02d", $hour, $min, $sec);
}

sub help {
    print STDERR <<EOF;
Usage: dnsq.pl <opt> < fqdn.list
opt:   -v        ; verbose mode
       -r <n>    ; 1..100 %
       -c <file> ; cache file
       -a        ; show authority
EOF
    exit 1;
}
