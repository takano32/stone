
			    Simple Repeater

			   stone version 2.2c

		Copyright(c)1995-2004 by Hiroaki Sengoku
			    sengoku@gcd.org


  stone は、アプリケーションレベルの TCP & UDP パケットリピーターです。
ファイアウォールの内から外へ、あるいは外から内へ、TCP パケットあるいは 
UDP パケットを中継します。

  stone には以下のような特徴があります。

1. Win32 に対応している
	以前は UNIX マシンで構成されることが多かったファイアウォールです
	が、最近は WindowsNT が使われるケースが増えてきました。stone は 
	WindowsNT あるいは Windows95 上で手軽に実行することができます。
	もちろん、Linux, FreeBSD, BSD/OS, SunOS, Solaris, HP-UX などの 
	UNIX マシンでも使うことができます。

2. 単純
	わずか 5000 行 (C 言語) ですので、セキュリティホールが生じる可能
	性を最小限にできます。

3. SSL 対応
	OpenSSL (http://www.openssl.org/) を使うことにより、暗号化/復号
	してパケットを中継できます。また、クライアント認証、あるいは サー
	バ認証を行ない、証明書のサブジェクトの一部を中継先へ送ることがで
	きます。

4. http proxy
	簡易型 http proxy としても使うことができます。

5. POP -> APOP 変換
	APOP に対応していないメーラと stone を使うことで、APOP サーバへ
	アクセスできます。


使用方法

	stone [-C <file>] [-P <command>] [-Q <options>] [-d] [-p] [-n]
	      [-u <max>] [-f <n>] [-l] [-L <file>] [-a <file>] [-i <file>]
	      [-X <n>] [-T <n>] [-r]
	      [-b <n> <master>:<port> <backup>:<port>]
	      [-B <host>:<port> <host1>:<port1>... --]
	      [-o <n>] [-g <n>] [-t <dir>] [-D] [-c <dir>]
	      [-q <SSL>] [-z <SSL>]
	      <st> [-- <st>]...

	-C はオプションおよび <st> をコマンドラインで指定するかわりに設
	定ファイルから読み込みます。-P は設定ファイルを読み込む際のプリ
	プロセッサを指定します。プリプロセッサへ与える引数は -Q で指定で
	きます。

	オプションとして -d を指定すると、デバッグレベルを増加させます。 
	-p を指定すると中継したデータをダンプします。-n を指定すると、ホ
	スト名やサービス名の代わりに IP アドレスやサービス番号を表示しま
	す。

	-u オプションは同時に記憶できる UDP パケットの発信元の最大数を指
	定します。デフォルトは 10 です。-f オプションは子プロセスの数を
	指定します。デフォルトは子プロセス無しです。

	-l を指定すると、エラーメッセージ等を syslog へ出力します。-L を
	指定すると、エラーメッセージ等を file へ出力します。-a を指定す
	ると、アクセスログを file へ出力します。-i は stone のプロセス 
	ID を出力するファイルを指定します。

	-X は中継を行なう際のバッファの大きさを指定します。デフォルトは 
	1000 バイトです。-T を指定すると TCP セッションのタイムアウトの
	秒数を変更できます。デフォルトは 600 (10 分) です。-r を指定する
	と <st> のソケットに SO_REUSEADDR を設定します。

	-b は中継先 <master>:<port> に接続できないときのバックアップとし
	て <backup>:<port> を指定します。すなわち <n> 秒ごとに 
	<master>:<port> に接続可能かチェックし、もし接続不可の場合は、中
	継先を <backup>:<port> へ変更します。

	-B は中継先グループの指定です。中継先が <host>:<port> である場合、
	このグループの中からランダムに一つの中継先を選んで中継します。

	-o と -g はそれぞれユーザ ID とグループ ID を指定します。ID は数
	字のみ指定可能です。-t を指定すると、dir へ chroot します。-D を
	指定すると、stone をデーモンとして起動します。-c はコアダンプを
	行なうディレクトリを指定します。

	-q および -z は、SSL 暗号化/復号 のオプションです。-q は、stone 
	が SSL クライアントとして、他の SSL サーバへ接続するとき、すなわ
	ち中継先が SSL サーバの時の、SSL オプションです。-z は stone が 
	SSL サーバとして、他の SSL クライアントからの接続を受付ける時の、
	SSL オプションです。

	<SSL> は SSL オプションで、次のいずれかです。

	default		SSL オプション指定をデフォルトに戻します。
			複数の <st> を指定する際、<st> 毎に異なる SSL オ
			プションを指定することができます。
	verbose		デバッグ用文字列をログに出力します。
	verify		SSL 接続相手に、SSL 証明書を要求します。
	verify,once	セッション開始時に一度だけ、
			SSL クライアントに証明書を要求します。(-z 専用)
	verify,ifany	SSL クライアントから証明書が送られてきたときのみ
			認証します。送られてこない場合は認証せずに
			セッションを開始します。(-z 専用)
	verify,none	SSL 接続相手に SSL 証明書を要求しません。
	uniq		SSL 接続相手の SSL 証明書のシリアル番号が前回の
			接続と異なる場合、接続を拒否します。
	re<n>=<regex>	SSL 証明書のチェーンが満たすべき正規表現を指定します。
			<n> は depth です。re0 が証明書のサブジェクト、
			re1 がその発行者を意味します。
			<n> は 9 まで指定できます。
	depth=<n>	SSL 証明書チェーンの長さの最大値を指定します。
			チェーンの長さがこの値を越えると認証が失敗します。
			<n> の最大値は 9 です。
	key=<file>	証明書の秘密鍵ファイルを指定します。
	cert=<file>	証明書ファイルを指定します。
	CAfile=<file>	認証局の証明書ファイルを指定します。
	CApath=<dir>	認証局の証明書があるディレクトリを指定します。
	cipher=<list>	暗号化アルゴリズムのリストを指定します。
	lb<n>=<m>	SSL 証明書の CN に応じて中継先を切り替えます。
			SSL オプションの re<n>= で指定した正規表現中、
			<n> 番目の ( ... ) 内の正規表現にマッチした文字
			列から算出した数値の剰余 <m> に基づいて、-B オプ
			ションで指定した中継先グループの中から中継先を選
			びます。

	<st> は次のいずれかです。<st> は「--」で区切ることにより、複数個
	指定できます。

	(1)	<host>:<port> <sport> [<xhost>...]
	(2)	<host>:<port> <shost>:<sport> [<xhost>...]
	(3)	<display> [<xhost>...]
	(4)	proxy <sport> [<xhost>...]
	(5)	<host>:<port>/http <request> [<xhost>...]
	(6)	<host>:<port>/proxy <header> [<xhost>...]
	(7)	health <sport> [<xhost>...]

	stone を実行しているマシンのポート <sport> への接続を、他のマシ
	ン <host> のポート <port> へ中継します。インタフェースを複数持つ
	マシンでは、(2) のようにインタフェースのアドレス <shost> を指定
	することにより、特定のインタフェースへの接続のみを転送することが
	できます。

	(3) は、X プロトコル中継のための省略記法です。ディスプレイ番号 
	<display> への接続を、環境変数 DISPLAY で指定した X サーバへ転送
	します。

	(4) は、http proxy です。WWW ブラウザの http proxy の設定で、
	stone を実行しているマシンおよびポート <sport> を指定します。

	(5) は、http リクエストにのせてパケットを中継します。<request> 
	は HTTP 1.0 で規定されるリクエストです。リクエスト文字列中、「\」
	はエスケープ文字であり、次のような置き換えが行なわれます。

		\n	改行 (0x0A)
		\r	復帰 (0x0D)
		\t	タブ (0x09)
		\\	\    (0x5C)
		\a	接続元の IP アドレス
		\A	「接続元の IP アドレス」:「ポート番号」
		\0	SSL 証明書のシリアル番号
		\1〜\9	SSL オプションの re<n>= で指定した正規表現中、
			( ... ) 内の正規表現にマッチした文字列

	(6) は、http リクエストヘッダの先頭に <header> を追加して中継し
	ます。(5) と同様のエスケープを使うことができます。

	(7) は、stone が正常に動作しているか検査するためのポートの指定で
	す。<sport> で指定したポートに接続して以下のコマンドを送信すると、
	stone の状態が返されます。

		HELO 任意の文字列	stone の状態の一覧を返す
		LIMIT <var> <n>		変数 <var> の値が <n> 未満か調べる

	<var> は次のうちのいずれかです。

		PAIR		pair の個数
		CONN		conn の個数
		ESTABLISHED	最後に接続確立してからの秒数
		READWRITE	最後に read or write してからの秒数
		ASYNC		スレッドの本数

	stone からの応答は、正常時は 200 番台、異常時は 500 番台の数値が
	先頭につきます。

	<xhost> を列挙することにより、stone へ接続可能なマシンを制限する
	ことができます。マシン名、あるいはその IP アドレスを空白で区切っ
	て指定すると、そのマシンからの接続のみを中継します。

	<xhost> に「/<mask>」を付けると、特定のネットワークのマシンから
	の接続を許可することができます。例えば、クラス C のネットワーク 
	192.168.1.0 の場合は、「192.168.1.0/255.255.255.0」と指定します。
	「192.168.1.0/24」などとビット数で指定することもできます。

	<xhost> の代わりに「!」を指定すると、後続の <xhost> は接続を拒否
	するマシンの指定になります。

	<sport> に「/udp」を付けると、TCP パケットを中継する代わりに、
	UDP パケットを中継します。

	<port> に「/apop」を付けると、POP を APOP へ変換して中継します。
	変換には RSA Data Security 社の MD5 Message-Digest アルゴリズム
	を使用します。

	<port> に「/ssl」を付けると、パケットを SSL で暗号化して中継します。

	<sport> に「/ssl」を付けると、SSL で暗号化されたパケットを復号し
	て中継します。

	<port> に「/base」を付けると、パケットを MIME base64 で符号化し
	て中継します。

	<sport> に「/base」を付けると、MIME base64 で符号化されたパケッ
	トを復号して中継します。

	<sport> に「/http」を付けると、http リクエスト上のパケットを中継
	します。

使用方法 (NT サービス版)

	stone -install		stone サービスをインストールします。
	stone -remove		stone サービスを削除します。
	stone -debug <params>	stone をアプリとして起動します。

	stone には自動的に「-C stone.cfg」が指定されます。すなわち、
	stone.exe と同じディレクトリにある設定ファイル stone.cfg に指定
	されたオプションが読み込まれます。


例
	outer: ファイアウォールの外側にあるマシン
	inner: ファイアウォールの内側にあるマシン
	fwall: ファイアウォール. このマシン上で stone を実行

	stone 7 outer
		DISPLAY で指定した X server へ X プロトコルを中継
		outer で DISPLAY=inner:7 と設定して X クライアントを実行

	stone outer:telnet 10023
		outer へ telnet プロトコルを中継
		inner で telnet fwall 10023 を実行

	stone outer:domain/udp domain/udp
		DNS 問い合わせを outer へ中継
		inner で nslookup - fwall を実行

	stone outer:ntp/udp ntp/udp
		outer へ NTP を中継
		inner で ntpdate fwall を実行

	stone localhost:http 443/ssl
		WWW サーバを https 対応にする
		WWW ブラウザで https://fwall/ をアクセス

	    注意: 輸出版 Netscape Navigator 等、多くの WWW ブラウザは 
		  512bit 超の鍵を扱えません

	stone localhost:telnet 10023/ssl
		telnet を SSL 化
		inner で SSLtelnet -z ssl fwall 10023 を実行

	stone proxy 8080
		http proxy

	stone outer:pop/apop pop
		APOP に対応していないメーラで inner:pop へ接続

	fwall が http proxy (port 8080) である時:

	stone fwall:8080/http 10023 'POST http://outer:8023 HTTP/1.0'
	stone localhost:telnet 8023/http
		inner と outer でそれぞれ stone を実行
		http 上でパケットを中継

	stone fwall:8080/proxy 9080 'Proxy-Authorization: Basic c2VuZ29rdTpoaXJvYWtp'
		proxy 認証に対応していないブラウザ用


ホームページ

	stone の公式ホームページは次の URL です。
	http://www.gcd.org/sengoku/stone/Welcome.ja.html


著作権

	この stone に関する全ての著作権は、原著作者である仙石浩明が所有
	します。この stone は、GNU General Public License (GPL) に準ずる
	フリーソフトウェアです。個人的に使用する場合は、改変・複製に制限
	はありません。配布する場合は GPL に従って下さい。また、openssl 
	とリンクして使用することを許可します。


無保証

	この stone は無保証です。この stone を使って生じたいかなる損害に
	対しても、原著作者は責任を負いません。詳しくは GPL を参照して下
	さい。


#2939								仙石 浩明
http://www.gcd.org/sengoku/		Hiroaki Sengoku <sengoku@gcd.org>
