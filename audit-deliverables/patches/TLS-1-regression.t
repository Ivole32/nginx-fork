#!/usr/bin/perl

# Regression test for GH-TLS-1 / finding TLS-1:
# per-vhost client-certificate policy must not be bypassable by omitting TLS SNI.
#
# Two server{} blocks share one TLS listen socket:
#   a.example  (default_server)  ssl_verify_client optional;  CA = ca-a
#   b.example  (protected)       ssl_verify_client on;        CA = ca-b
#
# A client that sends NO SNI handshakes under the default server (a.example, ca-a).
# If it then routes the request to b.example via the Host header while presenting a
# cert valid only under ca-a, the UNPATCHED server admits it (200) -- b.example's
# ca-b policy was never applied. The PATCHED server detects that the routed server
# differs from the server whose SSL_CTX performed the handshake and the routed
# server enforces verification, and returns 421 Misdirected Request -- matching the
# behaviour already used for the mismatching-SNI case.
#
# Modelled on nginx-tests ssl_verify_client.t and ssl_reject_handshake.t.
#
# NOTE: like the upstream SSL tests, this requires IO::Socket::SSL (socket_ssl_sni).
# Where that module is absent (as in this audit sandbox) the whole file SKIPs; the
# runnable equivalent is TLS-1-regression.sh (openssl s_client based).

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx qw/ :DEFAULT http_end /;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_ssl sni socket_ssl_sni/)
	->has_daemon('openssl')->plan(8);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key srv.key;
    ssl_certificate     srv.crt;

    ssl_session_cache off;
    ssl_session_tickets off;

    server {
        listen       127.0.0.1:8080 ssl default_server;
        server_name  a.example;

        ssl_client_certificate ca-a.crt;
        ssl_verify_client optional;

        location / {
            return 200 "server=A verify=$ssl_client_verify host=$host\n";
        }
    }

    server {
        listen       127.0.0.1:8080 ssl;
        server_name  b.example;

        ssl_client_certificate ca-b.crt;
        ssl_verify_client on;

        location / {
            return 200 "server=B verify=$ssl_client_verify host=$host\n";
        }
    }
}

EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

# server cert
system("openssl req -x509 -new -config $d/openssl.conf -subj /CN=srv/ "
	. "-out $d/srv.crt -keyout $d/srv.key >>$d/openssl.out 2>&1") == 0
	or die "Can't create server certificate: $!\n";

# two independent client CAs
foreach my $ca ('ca-a', 'ca-b') {
	system("openssl req -x509 -new -config $d/openssl.conf -subj /CN=$ca/ "
		. "-out $d/$ca.crt -keyout $d/$ca.key >>$d/openssl.out 2>&1") == 0
		or die "Can't create CA $ca: $!\n";
}

# client certs, each signed by one CA
my %signer = ('client-a' => 'ca-a', 'client-b' => 'ca-b');
foreach my $cn (sort keys %signer) {
	my $ca = $signer{$cn};
	system("openssl req -new -config $d/openssl.conf -subj /CN=$cn/ "
		. "-out $d/$cn.csr -keyout $d/$cn.key >>$d/openssl.out 2>&1") == 0
		or die "Can't create CSR $cn: $!\n";
	system("openssl x509 -req -in $d/$cn.csr -CA $d/$ca.crt -CAkey $d/$ca.key "
		. "-CAcreateserial -out $d/$cn.crt -days 1 "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't sign $cn with $ca: $!\n";
}

$t->run();

###############################################################################

# --- The security regression: no SNI, foreign (ca-a) cert, Host: b.example ---
# UNPATCHED: 200 (bypass).  PATCHED: 421 Misdirected Request.
like(get('none', 'client-a', 'b.example'), qr/421 Misdirected/,
	'no SNI, ca-a cert, Host b.example -> 421 (bypass closed)');

# unmatched SNI falls back to the default server, same gap/fix
like(get('zz.example', 'client-a', 'b.example'), qr/421 Misdirected/,
	'unmatched SNI, ca-a cert, Host b.example -> 421 (bypass closed)');

# --- Controls that must keep working ---

# no SNI, legitimately talking to the default server A
like(get('none', 'client-a', 'a.example'), qr/200 OK/,
	'no SNI, ca-a cert, Host a.example -> 200 (default server unaffected)');

# existing mismatching-SNI guard still returns 421
like(get('a.example', 'client-a', 'b.example'), qr/421 Misdirected/,
	'SNI a.example, Host b.example -> 421 (existing SNI guard)');

# legitimate b.example client over proper SNI still works
like(get('b.example', 'client-b', 'b.example'), qr/200 OK/,
	'SNI b.example, ca-b cert -> 200 (legit protected client)');

# no SNI, no cert, Host b.example: must be denied (not 200)
unlike(get('none', undef, 'b.example'), qr/200 OK/,
	'no SNI, no cert, Host b.example -> denied');

# no SNI, no cert, Host a.example: optional on A -> 200
like(get('none', undef, 'a.example'), qr/200 OK/,
	'no SNI, no cert, Host a.example -> 200 (optional on default)');

# plain (no cert) matched SNI to b.example must be denied (not 200)
unlike(get('b.example', undef, 'b.example'), qr/200 OK/,
	'SNI b.example, no cert -> denied');

###############################################################################

sub get {
	my ($sni, $cert, $host) = @_;

	# $sni eq 'none' => omit SNI entirely (empty SSL_hostname)
	my $hostname = ($sni eq 'none') ? '' : $sni;

	my $s = http(
		"GET / HTTP/1.0" . CRLF .
		"Host: $host" . CRLF . CRLF,
		start => 1,
		PeerAddr => '127.0.0.1:' . port(8080),
		SSL => 1,
		SSL_hostname => $hostname,
		$cert ? (
			SSL_cert_file => "$d/$cert.crt",
			SSL_key_file  => "$d/$cert.key"
		) : ()
	);

	return http_end($s);
}

###############################################################################
