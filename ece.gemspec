# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ece/version'

Gem::Specification.new do |spec|
  spec.name          = "ece"
  spec.version       = Ece::VERSION
  spec.authors       = ["Alexander Shevtsov"]
  spec.email         = ["randomlogin76@gmail.com"]

  spec.summary       = "Ruby implementation of encrypted content-encoding"
  spec.homepage      = "https://github.com/randomlogin/ece"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_dependency 'hkdf'
end
