require 'openssl'
require 'hkdf'
require 'base64'

#fore testing purposes only
#TODO: variable padding

class Ece
  
  KEY_LENGTH=16
  TAG_LENGTH=16
  NONCE_LENGTH=12

  def self.hmac_hash(key, input)
    digest = OpenSSL::Digest.new('sha256')
    OpenSSL::HMAC.digest(digest, key, input)
  end

  def self.hkdf_extract(salt, ikm)
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
    output[-6..-1] = [x.to_s(16)].pack('H*')
    output
  end

  def self.encrypt_record(params, counter, buffer, pad=0)
    raise "Key must be #{KEY_LENGTH} bytes long" unless params[:key].length == KEY_LENGTH
    gcm = OpenSSL::Cipher.new('aes-128-gcm')
    gcm.encrypt
    gcm.key = params[:key]
    gcm.iv = generate_nonce(params[:nonce], counter)
    enc = gcm.update("\x00"+buffer) + gcm.final + gcm.auth_tag  #enc = gcm.update("\x00"*pad+buffer)+gcm.final + gcm.auth_tag padding is not fully implemented for now
    enc
  end

  def self.encrypt(data, params)
    key = extract_key(params)
    rs = 4095 #look TODO
    result = ""
    counter = 0
    (0..data.length).step(rs) do |i|
      block = encrypt_record(key, counter, data[i..i+rs-1])
      result += block
      counter +=1
    end
    result
  end

  def self.decrypt_record(params, counter, buffer, pad=0)
    raise "Key must be #{KEY_LENGTH} bytes long" unless params[:key].length == KEY_LENGTH
    gcm = OpenSSL::Cipher.new('aes-128-gcm')
    gcm.decrypt
    gcm.key = params[:key]
    gcm.iv = generate_nonce(params[:nonce], counter)
    gcm.auth_tag = buffer[-16..-1]
    decrypted = gcm.update(buffer[0..-17]) + gcm.final
    #padding = decrypted[0]
    #padding_length = decrypted[0].unpack("C")
    #raise Err unless padding = "\x00"*padding_length
    decrypted[1..-1]
  end

  def self.decrypt(data, params)
    key = extract_key(params)
    rs = 4096+16 #not changeable for now
    result = ""
    counter = 0
    (0..buffer.length).step(rs) do |i|
      block = decrypt_record(key, counter, data[i..i+rs-1])
      result += block
      counter +=1
    end
    result
  end

end
