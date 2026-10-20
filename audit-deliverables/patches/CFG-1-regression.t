#!/usr/bin/perl

# GH-CFG-1 regression test for the Control API hardening:
#  (a) every control request is audit-logged with peer, method, path, status
#      (TCP: client address; unix socket: SO_PEERCRED uid/gid/pid);
#  (b) a non-loopback TCP listen address produces a warning.
# Expected to FAIL on an unpatched build (no audit line, no warning).

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

eval { require IO::Socket::UNIX; };
plan(skip_all => 'IO::Socket::UNIX not installed') if $@;

my $t = Test::Nginx->new()->has(qw/http rewrite control_api/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:8080;
        server_name  localhost;

        location / {
            return 200 "foo";
        }
    }
}

EOF

my $d = $t->testdir();
my $p = port(19100);

$t->args('-l', '127.0.0.1:' . $p)->run()->plan(14);

###############################################################################

# (a) TCP: audit line with client address, method, path and status

like(ctrl("GET /1/nginx HTTP/1.0"), qr/ 200 OK/, 'tcp get');
like(ctrl("PATCH /1/control/config HTTP/1.0"), qr/ 200 OK/, 'tcp reload');
like(ctrl("GET /1/nope HTTP/1.0"), qr/ 404 /, 'tcp not found');
like(ctrl("FOO / HTTP/1.0"), qr/ 405 /, 'tcp unknown method');
like(ctrl("GET /%41 HTTP/1.0"), qr/ 400 /, 'tcp bad request');

$t->stop();

my $log = $t->read_file('error.log');

like($log, qr/\[notice\] \d+#\d+: control: client 127\.0\.0\.1:\d+, "GET \/1\/nginx" 200$/m,
	'audit get');
like($log,
	qr/control: client 127\.0\.0\.1:\d+, "PATCH \/1\/control\/config" 200$/m,
	'audit reload');
like($log, qr/control: client 127\.0\.0\.1:\d+, "GET \/1\/nope" 404$/m,
	'audit not found');
like($log, qr/control: client 127\.0\.0\.1:\d+, "- \/" 405$/m,
	'audit unknown method');
like($log, qr/control: client 127\.0\.0\.1:\d+, "GET -" 400$/m,
	'audit bad request');

# (a) unix socket: SO_PEERCRED uid/pid of the connecting process (us)

$t->write_file('error.log', '');

my $path = "$d/ctrl.sock";
$t->args('-l', 'unix:' . $path)->run();

my $s = IO::Socket::UNIX->new(Peer => $path);
like(http("GET /1/control/processes HTTP/1.0" . "\x0d\x0a\x0d\x0a", socket => $s),
	qr/ 200 OK/, 'unix get');

$t->stop();

like($t->read_file('error.log'),
	qr/control: client unix uid:$< gid:\d+ pid:$$, "GET \/1\/control\/processes" 200$/m,
	'audit unix peer credentials');

# (b) non-loopback TCP address: warning is logged before bind()
# 192.0.2.1 (RFC 5737 TEST-NET-1) is not configured on any interface,
# so bind() fails and nothing reachable is ever opened.

$t->write_file('error.log', '');

system("timeout 10 $Test::Nginx::NGINX -p $d/ -c nginx.conf -e error.log "
	. "-l 192.0.2.1:$p >/dev/null 2>&1");

$log = $t->read_file('error.log');

like($log, qr/\[warn\] \d+#\d+: control: listening on non-loopback address "192\.0\.2\.1:$p" without authentication/,
	'non-loopback warning');

like($log, qr/control: bind\(\) failed/, 'non-loopback bind not possible here');

###############################################################################

sub ctrl {
	my ($line) = @_;

	my $s = IO::Socket::INET->new(
		Proto => 'tcp',
		PeerAddr => "127.0.0.1:$p"
	) or return;

	return http($line . "\x0d\x0a\x0d\x0a", socket => $s);
}

###############################################################################
