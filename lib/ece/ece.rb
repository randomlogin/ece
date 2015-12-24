require 'openssl'
require 'hkdf'
require 'base64'

#TODO: variable padding

class ECE

  KEY_LENGTH=16
  TAG_LENGTH=16
  NONCE_LENGTH=12

  def self.hmac_hash(key, input)
    digest = OpenSSL::Digest.new('sha256')
    OpenSSL::HMAC.digest(digest, key, input)
  end

  def self.hkdf_extract(salt, ikm) #ikm stays for input keying material
    hmac_hash(salt,ikm)
  end

  def self.extract_key(params)
    raise "Salt must be 16-bytes long" unless params[:salt].length==16
    key =  HKDF.new(params[:key], salt: params[:salt], algorithm: 'sha256', info: "Content-Encoding: aesgcm128")
    nonce =  HKDF.new(params[:key], salt: params[:salt], algorithm: 'sha256', info: "Content-Encoding: nonce")
    {key: key.next_bytes(KEY_LENGTH), nonce: nonce.next_bytes(NONCE_LENGTH)}
  end

  def self.generate_nonce(nonce, counter)
    raise "Nonce must be #{NONCE_LENGTH} bytes long." unless nonce.length == NONCE_LENGTH
    output = nonce.dup
    integer = nonce[-6..-1].unpack('B*')[0].to_i(2) #taking last 6 bytes, treating as integer
    x = ((integer ^ counter) & 0xffffff) + ((((integer / 0x1000000) ^ (counter / 0x1000000)) & 0xffffff) * 0x1000000)
    bytestring = x.to_s(16).length < 12 ? "0"*(12-x.to_s(16).length)+x.to_s(16) : x.to_s(16) #it's for correct handling of cases when generated integer is less than 6 bytes
    output[-6..-1] = [bytestring].pack('H*')                                                 #without it packing would produce less than 6 bytes
    output                                                                                   #I didn't find pack directive for such usage, so there is a such solution
  end

  def self.encrypt(data, params)
    key = extract_key(params)
    rs = params[:rs] ? params [:rs] : 4096
    raise "The rs parameter must be greater than 1." if rs <= 1
    rs -=1 #this ensures encrypted data cannot be truncated
    result = ""
    counter = 0
    (0..data.length).step(rs) do |i|
      block = encrypt_record(key, counter, data[i..i+rs-1])
      result += block
      counter +=1
    end
    result
  end

  def self.decrypt(data, params)
    key = extract_key(params)
    rs = params[:rs] ? params [:rs] : 4096
    raise "The rs parameter must be greater than 1." if rs <= 1
    rs += 16
    raise "Message is truncated" if data.length % rs == 0
    result = ""
    counter = 0
    (0..data.length).step(rs) do |i|
      block = decrypt_record(key, counter, data[i..i+rs-1])
      result += block
      counter +=1
    end
    result
  end

  def self.decrypt_record(params, counter, buffer, pad=0)
    gcm = OpenSSL::Cipher.new('aes-128-gcm')
    gcm.decrypt
    gcm.key = params[:key]
    gcm.iv = generate_nonce(params[:nonce], counter)
    raise "Block is too small" if buffer.length <= TAG_LENGTH+1
    gcm.auth_tag = buffer[-TAG_LENGTH..-1]
    decrypted = gcm.update(buffer[0..-TAG_LENGTH-1]) + gcm.final
    padding_length = decrypted[0].unpack("C")[0]
    raise "Padding is too big" if padding_length+1 > decrypted.length
    padding = decrypted[1..padding_length]
    raise "Wrong padding"  unless padding = "\x00"*padding_length
    decrypted[1..-1]
  end

  def self.encrypt_record(params, counter, buffer, pad=0)
    gcm = OpenSSL::Cipher.new('aes-128-gcm')
    gcm.encrypt
    gcm.key = params[:key]
    gcm.iv = generate_nonce(params[:nonce], counter)
    gcm.auth_data = "" 
    enc = gcm.update("\x00"+buffer) + gcm.final + gcm.auth_tag  #enc = gcm.update("\x00"*pad+buffer)+gcm.final + gcm.auth_tag padding is not fully implemented for now
    enc
  end


end
