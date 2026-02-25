use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== eq: string match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "admin";
  auth_require $var eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: string mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "guest";
  auth_require $var eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !eq: negated match (different value)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "guest";
  auth_require $var !eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !eq: negated match (same value fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "admin";
  auth_require $var !eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== gt: string greater
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "b";
  auth_require $var gt "a";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== gt: string not greater
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "a";
  auth_require $var gt "b";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== gt: string equal (not greater)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "a";
  auth_require $var gt "a";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== ge: string greater or equal (greater)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "b";
  auth_require $var ge "a";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== ge: string greater or equal (equal)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "a";
  auth_require $var ge "a";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== ge: string not greater or equal
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "a";
  auth_require $var ge "b";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== lt: string less
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "a";
  auth_require $var lt "b";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== lt: string not less
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "b";
  auth_require $var lt "a";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== le: string less or equal (less)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "a";
  auth_require $var le "b";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== le: string less or equal (equal)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "a";
  auth_require $var le "a";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== le: string not less or equal
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "b";
  auth_require $var le "a";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== in: value in JSON array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "admin";
  auth_require $var in json=["staff","admin","viewer"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== in: value not in JSON array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "guest";
  auth_require $var in json=["staff","admin","viewer"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !in: negated in (not contained)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "guest";
  auth_require $var !in json=["staff","admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !in: negated in (contained fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "admin";
  auth_require $var !in json=["staff","admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== match: regex match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "sk-abc123XYZ";
  auth_require $var match "^sk-[a-zA-Z0-9]+";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== match: regex no match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "invalid-key";
  auth_require $var match "^sk-[a-zA-Z0-9]+";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !match: negated regex (no match passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "invalid";
  auth_require $var !match "^sk-";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !match: negated regex (match fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "sk-abc";
  auth_require $var !match "^sk-";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== match: email pattern
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "user@example.com";
  auth_require $var match "@example\.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== match: email pattern no match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "user@other.org";
  auth_require $var match "@example\.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== match: \z anchor as $ workaround (match)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "admin";
  auth_require $var match "^admin\\z";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== match: \z anchor as $ workaround (no match)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "admin-extra";
  auth_require $var match "^admin\\z";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== custom error: comparison with error=401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "guest";
  auth_require $var eq "admin" error=401;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401

=== multiple comparison directives: both pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "admin";
  auth_require $var eq "admin";
  auth_require $var !eq "guest";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== multiple comparison directives: second fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "admin";
  auth_require $var eq "admin";
  auth_require $var eq "superadmin" error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== variable from request: arg match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_require $arg_token eq "secret123";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?token=secret123
--- error_code: 200

=== variable from request: arg mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_require $arg_token eq "secret123";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?token=wrong
--- error_code: 403

=== match: dynamic pattern with variable
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "hello-world";
  set $pat "^hello";
  auth_require $var match $pat;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== match: dynamic pattern mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "goodbye";
  set $pat "^hello";
  auth_require $var match $pat;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== config error: invalid regex pattern rejected at config time
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "test";
  auth_require $var match "[invalid";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== config error: unknown operator name
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "test";
  auth_require $var foo "bar";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== empty variable: eq empty string passes
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_require $arg_missing eq "";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== empty variable: eq non-empty string fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  auth_require $arg_missing eq "value";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403
