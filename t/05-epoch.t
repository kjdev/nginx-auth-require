use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== exp gt epoch: future exp passes (token valid)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_exp_future .exp gt json=$auth_gate_epoch;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== exp gt epoch: past exp fails (token expired)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_exp_past .exp gt json=$auth_gate_epoch;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== nbf le epoch: past nbf passes (token active)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_nbf_past .nbf le json=$auth_gate_epoch;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== nbf le epoch: future nbf fails (token not yet valid)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_gate_jwt $jwt_nbf_future .nbf le json=$auth_gate_epoch;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== epoch variable expansion via add_header
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  add_header X-Epoch $auth_gate_epoch;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200
--- response_headers_like
X-Epoch: ^\d+$
