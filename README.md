### Gem is no longer supported, use at your own risk.

# ECE

Ruby implementation of encrypted content-encoding.

https://tools.ietf.org/html/draft-thomson-http-encryption-02

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ece'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install ece

## Usage

Encrypting:

```ruby
require 'ece'

key = Random.new.bytes(16)
salt = Random.new.bytes(16)
data = "Your very private data"

encrypted_data = ECE.encrypt(data, key: key, salt: salt)
```
Decrypting:

```ruby
ECE.decrypt(encrypted_data, key: key, salt: salt)
```
Data can be bytestring as well.

Encrypting data with elliptical curve Diffie-Hellman (ECDH) key agreement
protocol using client keys providing by a [Web Push subscription](https://developer.mozilla.org/en-US/docs/Web/API/PushSubscription/getKey):

```ruby
user_public_key # Provided by the browser, effectively: Random.new.bytes(65)
user_auth # Provided by the browser, effectively: Random.new.bytes(16)

local_curve = OpenSSL::PKey::EC.new("prime256v1")
local_curve.generate_key
user_public_key_point = OpenSSL::PKey::EC::Point.new(local_curve.group, OpenSSL::BN.new(user_public_key, 2))

key = local_curve.dh_compute_key(user_public_key_point)
server_public_key = local_curve.public_key.to_bn.to_s(2)
salt = Random.new.bytes(16)

encrypted_data = ECE.encrypt(data,
  key: key,
  salt: salt
  server_public_key: server_public_key,
  user_public_key: user_public_key,
  auth: user_auth)
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/randomlogin/ece.
