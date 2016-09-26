<?php
// jwt.php is a test script
// Usage:
//     php -d extension=modules/jwt.so -f jwt.php
echo "---- Test: encode and decode with default config (alg: HS256)\n";
$payload = [
	"number" => 1234567890,
	"bool" => true,
    "string" => "foo",
    "array" => ["aaa", "bbb", "ccc"],
];
$key = "secret";

// encode
$token = jwt_encode($payload, $key);
// var_dump($payload);
echo "[info] token = $token\n";

// decode
$decoded_payload = jwt_decode($token, $key, true, ["HS256"]);
// var_dump($decoded_payload);

if ($payload === $decoded_payload) {
	echo "Pass!\n\n";
} else {
	echo "Fail!\n";
	echo "Expected:\n";
	var_dump($payload);
	echo "Actual:\n";
	var_dump($decoded_payload);
    exit(1);
}


echo "---- Test: encode and decode (alg: HS384)\n";
$payload = [
	"number" => 1234567890,
	"bool" => true,
    "string" => "foo",
    "array" => ["aaa", "bbb", "ccc"],
];
$key = "secret";

// encode
$token = jwt_encode($payload, $key, "HS384");
// var_dump($payload);
echo "[info] token = $token\n";

// decode
$decoded_payload = jwt_decode($token, $key, true, ["HS384"]);
// var_dump($decoded_payload);

if ($payload === $decoded_payload) {
	echo "Pass!\n\n";
} else {
	echo "Fail!\n";
	echo "Expected:\n";
	var_dump($payload);
	echo "Actual:\n";
	var_dump($decoded_payload);
    exit(1);
}


echo "---- Test: encode and decode (alg: HS512)\n";
$payload = [
	"number" => 1234567890,
	"bool" => true,
    "string" => "foo",
    "array" => ["aaa", "bbb", "ccc"],
];
$key = "secret";

// encode
$token = jwt_encode($payload, $key, "HS512");
// var_dump($payload);
echo "[info] token = $token\n";

// decode
$decoded_payload = jwt_decode($token, $key, true, ["HS512"]);
// var_dump($decoded_payload);

if ($payload === $decoded_payload) {
	echo "Pass!\n\n";
} else {
	echo "Fail!\n";
	echo "Expected:\n";
	var_dump($payload);
	echo "Actual:\n";
	var_dump($decoded_payload);
    exit(1);
}


echo "---- Test: encode and decode as a php object\n";
$payload = new stdClass;
$payload->number = 1234567890;
$payload->bool = true;
$payload->string = "foo";
$payload->array = ["aaa", "bbb", "ccc"];
$key = "secret";

// encode
$token = jwt_encode($payload, $key);
// var_dump($payload);
echo "[info] token = $token\n";

// decode
$decoded_payload = jwt_decode($token, $key);
// var_dump($decoded_payload);

if ($payload == $decoded_payload) {
	echo "Pass!\n\n";
} else {
	echo "Fail!\n";
	echo "Expected:\n";
	var_dump($payload);
	echo "Actual:\n";
	var_dump($decoded_payload);
    exit(1);
}

// $jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsImFkbWluIjp0cnVlfQ.PfNTLhA7RRxBSDc_t4gkx9NhDJQ1DivtTGHyOywAkqY";
// $key = "secret";
//
// var_dump(jwt_decode($jwt, $key));
