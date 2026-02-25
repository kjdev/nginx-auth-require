use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== valid: non-empty variable
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "active";
  auth_require $var;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== invalid: empty variable
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "";
  auth_require $var;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== invalid: variable is "0"
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "0";
  auth_require $var;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== valid: variable is "1"
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "1";
  auth_require $var;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== valid: variable is non-zero string
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "00";
  auth_require $var;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== valid: multiple variables all truthy
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var1 "a";
  set $var2 "b";
  set $var3 "c";
  auth_require $var1 $var2 $var3;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== invalid: multiple variables, first empty
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var1 "";
  set $var2 "b";
  auth_require $var1 $var2;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== invalid: multiple variables, second empty
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var1 "a";
  set $var2 "";
  auth_require $var1 $var2;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== invalid: multiple variables, second is "0"
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var1 "a";
  set $var2 "0";
  auth_require $var1 $var2;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== custom error code: error=401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "";
  auth_require $var error=401;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401

=== custom error code: valid with error=401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "ok";
  auth_require $var error=401;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== multiple directives: AND logic, both pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var1 "a";
  set $var2 "b";
  auth_require $var1;
  auth_require $var2;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== multiple directives: AND logic, second fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var1 "a";
  set $var2 "";
  auth_require $var1 error=401;
  auth_require $var2 error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== multiple directives: AND logic, first fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var1 "";
  set $var2 "b";
  auth_require $var1 error=401;
  auth_require $var2 error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401

=== map variable: valid
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $arg_role $is_admin {
  "admin" 1;
  default 0;
}
--- config
location / {
  auth_require $is_admin error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?role=admin
--- error_code: 200

=== map variable: invalid
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
map $arg_role $is_admin {
  "admin" 1;
  default 0;
}
--- config
location / {
  auth_require $is_admin error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /?role=guest
--- error_code: 403

=== config error: error=499 is rejected
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "ok";
  auth_require $var error=499;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== config error: error=399 out of range
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "ok";
  auth_require $var error=399;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== config error: error=600 out of range
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "ok";
  auth_require $var error=600;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== error=400: lower boundary accepted
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "";
  auth_require $var error=400;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 400

=== error=599: upper boundary accepted
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $var "";
  auth_require $var error=599;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 599
