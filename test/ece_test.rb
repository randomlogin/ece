require 'test/unit'
require 'ece'


class TestECE < Test::Unit::TestCase


  def encrypt_decrypt(len=rand(1..500), params={key: Random.new.bytes(16), salt:Random.new.bytes(16)})
    input = Random.new.bytes(len)
    encrypted = ECE.encrypt(input, params)
    decrypted = ECE.decrypt(encrypted, params)
    assert_equal(input, decrypted)
  end

  def encrypt_decrypt_with_auth(len=rand(1..5000), params={key: Random.new.bytes(16), salt:Random.new.bytes(16),
                                                           auth: Random.new.bytes(16), user_public_key: Random.new.bytes(16), server_public_key: Random.new.bytes(16)})
    input = Random.new.bytes(len)
    encrypted = ECE.encrypt(input, params)
    decrypted = ECE.decrypt(encrypted, params)
    assert_equal(input, decrypted)
  end


  def test_simple_workflow
    (0..20).each do |i|
      encrypt_decrypt
    end
  end

  def test_simple_workflow_with_auth
    (0..20).each do |i|
      encrypt_decrypt_with_auth
    end
  end


  def test_wrong_record_size_
    assert_raise(RuntimeError) {encrypt_decrypt(rand(1..5000), {salt: Random.new.bytes(16), key: Random.new.bytes(16), rs: 1}) }
  end


  def test_wrong_salt
    assert_raise(RuntimeError) {encrypt_decrypt(rand(1..5000), {salt: Random.new.bytes(10), key: Random.new.bytes(20)}) }
  end

  def test_trancated_message
    rs = rand(2..8000)
    len = rand(10*(rs+16)..20*(rs+16))
    truncation = rand(1..10)*(rs+16)-1
    params = {salt: Random.new.bytes(16), key: Random.new.bytes(16), rs: rs}
    assert_raise(RuntimeError) do
      encrypted = ECE.encrypt(Random.new.bytes(len), params)
      ECE.decrypt(encrypted[0..truncation], params)
    end
  end

  def test_message_is_broken
    rs = rand(2..8000)
    len = rand(10*(rs+16)..20*(rs+16))
    truncation = rand(1..10)*(rs+16)+rand(16)
    params = {salt: Random.new.bytes(16), key: Random.new.bytes(16), rs: rs}
    assert_raise(RuntimeError) do
      encrypted = ECE.encrypt(Random.new.bytes(len), params)
      ECE.decrypt(encrypted[0..truncation], params)
    end
  end


end
