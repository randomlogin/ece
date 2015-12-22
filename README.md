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
## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/randomlogin/ece.

