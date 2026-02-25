use Test::Nginx::Socket 'no_plan';

no_root_location();
no_shuffle();

run_tests();

__DATA__

=== eq: root value check
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '"hello"';
  auth_require_json $val . eq "hello";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: simple field match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: simple field mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role eq "guest";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !eq: negated equal (different value passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role !eq "guest";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !eq: negated equal (same value fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role !eq "admin";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== eq: empty string check
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .sub eq "";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !eq: empty string negation (non-empty passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .sub !eq "";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: boolean with json= prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .verified eq json=true;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: true mismatch (field is false)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .verified eq json=true;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !eq: negated true (field is false, passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .verified !eq json=true;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !eq: negated true (field is true, fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .verified !eq json=true;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== eq: false match (field is false)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .verified eq json=false;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: false mismatch (field is true)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .verified eq json=false;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !eq: negated false (field is true, passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .verified !eq json=false;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: null match (field is null)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json_with_null '{"status":null,"name":"test"}';
  auth_require_json $json_with_null .status eq json=null;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: null mismatch (field is not null)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json_with_null '{"status":null,"name":"test"}';
  auth_require_json $json_with_null .name eq json=null;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !eq: negated null (field is not null, passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json_with_null '{"status":null,"name":"test"}';
  auth_require_json $json_with_null .name !eq json=null;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !eq: negated null (field is null, fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json_with_null '{"status":null,"name":"test"}';
  auth_require_json $json_with_null .status !eq json=null;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== gt: numeric greater than (json= expected)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .age gt json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== gt: numeric not greater than
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .age gt json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== ge: numeric greater or equal (greater)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== ge: numeric greater or equal (equal)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .age ge json=25;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== ge: numeric not greater or equal
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .age ge json=30;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== lt: numeric less than
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .age lt json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== lt: numeric not less than
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .age lt json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== le: numeric less or equal (less)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .age le json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== le: numeric less or equal (equal)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .age le json=15;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== le: numeric not less or equal
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .age le json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== in: value in json= array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role in json=["staff","admin","viewer"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== in: value not in json= array
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .role in json=["staff","admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !in: negated in (not contained passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .role !in json=["staff","admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !in: negated in (contained fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role !in json=["staff","admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== any: arrays share common element
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .groups any json=["staff","viewer"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== any: arrays have no common element
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .groups any json=["viewer","manager"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !any: negated any (no common element passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .groups !any json=["viewer","manager"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== !any: negated any (common element fails)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .groups !any json=["staff","viewer"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== match: regex on string field
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .email match "@example\.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== match: regex no match
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .email match "@example\.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== !match: negated regex (no match passes)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .email !match "@example\.com";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== nested field: dot notation
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .nested.key eq "value";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== nested field: mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .nested.key eq "wrong";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== array index: first element
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .keys[0] eq "primary";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== array index: second element
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .keys[1] eq "secondary";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== array index: mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .keys[0] eq "secondary";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== field not found
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .nonexistent eq "value";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== invalid JSON variable
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $bad_json "not json";
  auth_require_json $bad_json .field eq "value";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== custom error code: error=401
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_guest .role eq "admin" error=401;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401

=== multiple directives: AND logic, both pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role eq "admin";
  auth_require_json $json_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== multiple directives: AND logic, second fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role eq "admin";
  auth_require_json $json_admin .age lt json=18 error=403;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== eq: integer with json= prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .age eq json=25;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: integer mismatch with json= prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .age eq json=30;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== eq: array comparison with json= prefix
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .groups eq json=["admin","staff"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== eq: array comparison mismatch
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .groups eq json=["admin"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== grouping: same variable 3 rules, all pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role eq "admin";
  auth_require_json $json_admin .age ge json=18;
  auth_require_json $json_admin .verified eq json=true;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== grouping: same variable 3 rules, middle fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role eq "admin";
  auth_require_json $json_admin .age lt json=18;
  auth_require_json $json_admin .verified eq json=true;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== grouping: same variable, custom error in group
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role eq "admin";
  auth_require_json $json_admin .age gt json=30 error=401;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 401

=== grouping: two variables, all pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role eq "admin";
  auth_require_json $json_guest .role eq "guest";
  auth_require_json $json_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== grouping: two variables, second group fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
location / {
  auth_require_json $json_admin .role eq "admin";
  auth_require_json $json_guest .role eq "admin";
  auth_require_json $json_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== grouping: inherited from server, all pass
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
auth_require_json $json_admin .role eq "admin";
location / {
  auth_require_json $json_admin .age ge json=18;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== grouping: inherited from server, child fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
include $TEST_NGINX_CONF_DIR/variables.conf;
auth_require_json $json_admin .role eq "admin";
location / {
  auth_require_json $json_admin .age gt json=30;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== bracket escape: key with escaped quote
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"a\\"b":"found"}';
  auth_require_json $val '.["a\\"b"]' eq "found";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== bracket escape: key with escaped backslash
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"a\\\\b":"found"}';
  auth_require_json $val '.["a\\\\b"]' eq "found";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== scalar json: root dot path returns scalar
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '42';
  auth_require_json $val . eq json=42;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== scalar json: non-root path on scalar fails (403)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '"just_a_string"';
  auth_require_json $val .key eq "anything";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== large integer: gt comparison with Snowflake-sized IDs
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"id":9007199254740993}';
  auth_require_json $val .id gt json=9007199254740992;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== large integer: eq comparison with identical large values
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"id":9007199254740993}';
  auth_require_json $val .id eq json=9007199254740993;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== large integer: lt comparison across precision boundary
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"id":9007199254740992}';
  auth_require_json $val .id lt json=9007199254740993;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== empty array: in with empty array fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"role":"admin"}';
  auth_require_json $val .role in json=[];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== empty array: any with empty actual array fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"tags":[]}';
  auth_require_json $val .tags any json=["a"];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== empty array: !in with empty array passes
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"role":"admin"}';
  auth_require_json $val .role !in json=[];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== any: compare count limit exceeded returns 403
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"a":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101]}';
  auth_require_json $val .a any json=[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101];
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403

=== mixed numeric comparison: integer ge real (lossless promotion)
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"x":100}';
  auth_require_json $val .x ge json=100.0;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== mixed numeric comparison: integer gt real
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $val '{"x":101}';
  auth_require_json $val .x gt json=100.0;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== invalid escape sequence in bracket key
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"key":"value"}';
  auth_require_json $json '.["ke\\ny"]' eq "value";
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- must_die

=== negative number comparison: -5 gt -10 passes
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"x":-5}';
  auth_require_json $json .x gt json=-10;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 200

=== negative number comparison: -5 lt -10 fails
--- http_config
include $TEST_NGINX_CONF_DIR/authorized_server.conf;
--- config
location / {
  set $json '{"x":-5}';
  auth_require_json $json .x lt json=-10;
  include $TEST_NGINX_CONF_DIR/authorized_proxy.conf;
}
--- request
GET /
--- error_code: 403
