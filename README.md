# php-jwt

A php extension to encode and decode JSON Web Tokens (JWT).

> This is experimental (and dirty) implementation. Do not use it for your production environment!

Table of Contents

* [Installation](#installation)
* [Functions](#functions)
  * [jwt_encode](#jwt_encode)
  * [jwt_decode](#jwt_decode)
* [Author](#author)
* [License](#license)
* [See Also](#see-also)
* [Inspired By](#inspired-by)

## Installation

Make the extension:

```
phpize
./configure
make
make install
```

Add the following line to `php.ini` to load the extension:

```
extension=jwt.so
```

This extension supports PHP5.4 ~ 5.6. **NOT** support PHP7.

## Functions

### jwt_encode

jwt_encode - Returns the JWT encoded string.

```
string jwt_encode ( mixed $payload, string $key [, string $alg = "HS256" [, array $header ]] )
```

#### Parameters

* `payload` (array|object): The payload being encoded.

* `key` (string): The secret key. If the algorithm used is asymmetric, this is the private key.

* `alg` (string): The signing algorithm. Default `HS256`. Now, supported algorithms are 'HS256', 'HS384' and 'HS512'.

* `header` (array): An array with header elements to attach.

#### Return Value

JWT encoded string. If this function fails, it returns **FALSE**.

#### Example

```php
$payload = ["user_id" => "1234567890", "admin" => true];
$key = "secret";

echo jwt_encode($payload, $key);
```

The above example will output:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsImFkbWluIjp0cnVlfQ.PfNTLhA7RRxBSDc_t4gkx9NhDJQ1DivtTGHyOywAkqY
```

### jwt_decode

jwt_decode — Decodes a JWT string.

```
mixed jwt_decode ( string $jwt, mixed $key [, bool $assoc = false [, array $allowed_algs = array("HS256") ]] )
```

#### Parameters

* `jwt` (string): The JWT string

* `key` (string|array):  The key, or map of keys. If the algorithm used is asymmetric, this is the public key.

* `assoc` (bool): When **TRUE**, returned objects will be converted into associative arrays.

* `allowed_algs` (array): List of supported verification algorithms. Default `HS256`. Supported algorithms are 'HS256', 'HS384' and 'HS512'.

#### Return Value

Object The JWT's payload as a PHP object or array. If this function fails or signature verification fails, it returns **FALSE**.

#### Example

```php
$jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiMTIzNDU2Nzg5MCIsImFkbWluIjp0cnVlfQ.PfNTLhA7RRxBSDc_t4gkx9NhDJQ1DivtTGHyOywAkqY";
$key = "secret";

var_dump(jwt_decode($jwt, $key));
```

The above example will output:

```
class stdClass#3 (2) {
  public $user_id =>
  string(10) "1234567890"
  public $admin =>
  bool(true)
}
```

## Author

Kohki Makimoto <kohki.makimoto@gmail.com>

## License

The MIT License (MIT)

## See Also

* [RFC 7519](https://tools.ietf.org/html/rfc7519).
* [jwt.io](https://jwt.io/)

## Inspired By

* [https://github.com/firebase/php-jwt](https://github.com/firebase/php-jwt)
* [https://github.com/benmcollins/libjwt](https://github.com/benmcollins/libjwt)
