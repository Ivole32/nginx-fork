#!/usr/bin/perl

# Regression test for audit finding GH-HTTP-1 (HTTP-1 / HTTP-2 / HTTP-F-1).
#
# (a) config-time warning: "tunnel_pass" placed in a location that can never
#     be matched by a CONNECT request (whose URI is always "/") must produce a
#     "[warn]" at configuration test time; "location / { tunnel_pass; }" must
#     not.  Fails on an unpatched binary, passes with patches/HTTP-1.diff.
#
# (b) reference hardening configuration for the zero-argument form of
#     "tunnel_pass" (target = client-controlled $host:$request_port): a map on
#     "$host:$request_port" allow-lists destination host(s) and port(s) and
#     everything else gets "return 403".  Passes on patched and unpatched
#     binaries (pure configuration).

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http tunnel rewrite/);

# Part (a): configuration-time warning ---------------------------------------

$t->write_file_expand('warn.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_19283%%;
        server_name  localhost;

        location / {
            return 200;
        }

        location = /x {
            tunnel_pass;
        }
    }
}

EOF

$t->write_file_expand('nowarn.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_19283%%;
        server_name  localhost;

        location / {
            tunnel_pass;
        }
    }
}

EOF

# Part (b): reference hardening configuration --------------------------------
#
# In production keep only "443" in the port alternation; the test cannot bind
# 443, so the backend port stands in for it.  Hosts are allow-listed, not
# deny-listed: $host for CONNECT is the request-line authority (lower-cased,
# trailing dot stripped) and a deny-list is trivially bypassed with
# "localhost", "[::1]", "[::ffff:127.0.0.1]", a DNS name that resolves to
# loopback, etc.

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    resolver 127.0.0.1:%%PORT_19290_UDP%%;
    resolver_timeout 1s;

    tunnel_connect_timeout 1s;
    tunnel_read_timeout 1s;

    map "$host:$request_port" $tunnel_allowed {
        default                                        0;
        "~^allowed\.example:(443|%%PORT_19281%%)$"     1;
    }

    server {
        listen       127.0.0.1:%%PORT_19280%%;
        server_name  localhost;

        location / {
            if ($tunnel_allowed = 0) {
                return 403;
            }

            tunnel_pass;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_19281%%;
        server_name  localhost;

        location / {
            return 200 "SEE-THIS";
        }
    }
}

EOF

$t->run_daemon(\&dns_daemon, $t)->waitforfile($t->testdir . '/' . port(19290))
	or die "dns daemon failed to start\n";

$t->try_run('no tunnel')->plan(11);

###############################################################################

# (a)

{
	local $ENV{ASAN_OPTIONS} = 'detect_leaks=0';

	my $out = config_test($t, 'warn.conf');
	like($out, qr/\[warn\] (?:\d+#\d+: )?"tunnel_pass" in location "\/x" cannot be reached/,
		'warning for tunnel_pass in location = /x');
	like($out, qr/syntax is ok/, 'warn.conf still valid');

	$out = config_test($t, 'nowarn.conf');
	unlike($out, qr/\[warn\]/, 'no warning for tunnel_pass in location /');
	like($out, qr/syntax is ok/, 'nowarn.conf valid');
}

# (b)

my $p = port(19280);
my $backend = port(19281);
my $other = port(19282);

like(proxy_get('/', "127.0.0.1:$backend", $p), qr/^HTTP\/1\.1 403 /,
	'loopback IP blocked');
like(proxy_get('/', "127.0.0.1:443", $p), qr/^HTTP\/1\.1 403 /,
	'loopback IP on allowed port blocked');
like(proxy_get('/', "localhost:443", $p), qr/^HTTP\/1\.1 403 /,
	'localhost blocked');
like(proxy_get('/', "[::1]:443", $p), qr/^HTTP\/1\.1 403 /,
	'IPv6 loopback literal blocked');
like(proxy_get('/', "allowed.example:$other", $p), qr/^HTTP\/1\.1 403 /,
	'allowed host, non-allowed port blocked');
like(proxy_get('/', "allowed.example:$backend", $p), qr/SEE-THIS/,
	'allowed host and port tunnelled');
like(proxy_get('/', "ALLOWED.EXAMPLE.:$backend", $p), qr/SEE-THIS/,
	'allowed host, case and trailing dot normalised');

###############################################################################

sub config_test {
	my ($t, $conf) = @_;
	my $testdir = $t->testdir();

	my $out = `$Test::Nginx::NGINX -t -p $testdir -c $testdir/$conf 2>&1`;
	Test::Nginx::log_core('|', $out);
	return $out;
}

sub proxy_get {
	my ($uri, $host, $proxy_port, %extra) = @_;
	my $reply = '';

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => '127.0.0.1:' . $proxy_port,
	)
		or die "Can't connect to proxy 127.0.0.1:$proxy_port $!\n";

	http(<<EOF, socket => $s, start => 1, %extra);
CONNECT $host HTTP/1.1
Host: $host

EOF

	while (<$s>) {
		$reply .= $_;
		last if /^\r?\n$/;
	}

	if ($reply =~ /200 OK/) {
		log_in($reply);
		return http_get($uri, socket => $s, %extra);

	} elsif ($reply =~ /Content-Length:\s*(\d+)/i) {
		read ($s, $_, $1);
		$reply .= $_;
	}

	$s->close;
	log_in($reply);
	return $reply;
}

###############################################################################

sub reply_handler {
	my ($recv_data, $port, %extra) = @_;

	my (@name, @rdata);

	use constant NOERROR	=> 0;
	use constant A		=> 1;
	use constant IN		=> 1;

	my ($hdr, $rcode, $ttl) = (0x8180, NOERROR, 3600);

	my ($len, $offset) = (undef, 12);
	while (1) {
		$len = unpack("\@$offset C", $recv_data);
		last if $len == 0;
		$offset++;
		push @name, unpack("\@$offset A$len", $recv_data);
		$offset += $len;
	}

	$offset -= 1;
	my ($id, $type, $class) = unpack("n x$offset n2", $recv_data);

	my $name = join('.', @name);
	if ($name eq 'allowed.example') {
		if ($type == A) {
			push @rdata, rd_addr($ttl, '127.0.0.1');
		}
	}

	$len = @name;
	pack("n6 (C/a*)$len x n2", $id, $hdr | $rcode, 1, scalar @rdata,
		0, 0, @name, $type, $class) . join('', @rdata);
}

sub rd_addr {
	my ($ttl, $addr) = @_;

	my $code = 'split(/\./, $addr)';

	return pack 'n3N', 0xc00c, A, IN, $ttl if $addr eq '';

	pack 'n3N nC4', 0xc00c, A, IN, $ttl, eval "scalar $code", eval($code);
}

sub dns_daemon {
	my ($t) = @_;

	my ($data, $recv_data);
	my $socket = IO::Socket::INET->new(
		LocalAddr => '127.0.0.1',
		LocalPort => port(19290),
		Proto => 'udp',
	)
		or die "Can't create listening socket: $!\n";

	open my $fh, '>', $t->testdir() . '/' . port(19290);
	close $fh;

	while (1) {
		$socket->recv($recv_data, 65536);
		$data = reply_handler($recv_data);
		$socket->send($data);
	}
}

###############################################################################
