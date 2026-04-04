require "base64"
require "digest"
require "json"
require "openssl"
require "zlib"

module Tripwire
  module Server
    module SealedToken
      VERSION = 0x01

      module_function

      def verify_tripwire_token(sealed_token, secret_key = nil)
        CryptoSupport.ensure_supported_runtime!
        resolved_secret = secret_key || ENV["TRIPWIRE_SECRET_KEY"]
        raise ConfigurationError, "Missing Tripwire secret key. Pass secret_key explicitly or set TRIPWIRE_SECRET_KEY." if resolved_secret.nil? || resolved_secret.empty?

        raw = Base64.decode64(sealed_token)
        raise TokenVerificationError, "Tripwire token is too short." if raw.bytesize < 29

        version = raw.getbyte(0)
        raise TokenVerificationError, "Unsupported Tripwire token version: #{version}" if version != VERSION

        nonce = raw.byteslice(1, 12)
        ciphertext = raw.byteslice(13, raw.bytesize - 29)
        tag = raw.byteslice(raw.bytesize - 16, 16)

        cipher = OpenSSL::Cipher.new("aes-256-gcm")
        cipher.decrypt
        cipher.key = derive_key(resolved_secret)
        cipher.iv = nonce
        cipher.auth_tag = tag
        cipher.auth_data = ""

        compressed = cipher.update(ciphertext) + cipher.final
        payload = JSON.parse(Zlib::Inflate.inflate(compressed))
        deep_symbolize(payload)
      rescue ConfigurationError, TokenVerificationError
        raise
      rescue StandardError => error
        raise TokenVerificationError, "Failed to verify Tripwire token: #{error.message}"
      end

      def safe_verify_tripwire_token(sealed_token, secret_key = nil)
        { ok: true, data: verify_tripwire_token(sealed_token, secret_key) }
      rescue ConfigurationError, TokenVerificationError => error
        { ok: false, error: error }
      end

      def derive_key(secret_key_or_hash)
        Digest::SHA256.digest("#{normalize_secret(secret_key_or_hash)}\0sealed-results")
      end
      private_class_method :derive_key

      def normalize_secret(secret_key_or_hash)
        return secret_key_or_hash.downcase if /\A[0-9a-fA-F]{64}\z/.match?(secret_key_or_hash)

        Digest::SHA256.hexdigest(secret_key_or_hash)
      end
      private_class_method :normalize_secret

      def deep_symbolize(value)
        case value
        when Array
          value.map { |item| deep_symbolize(item) }
        when Hash
          value.each_with_object({}) do |(key, item), memo|
            memo[key.to_sym] = deep_symbolize(item)
          end
        else
          value
        end
      end
      private_class_method :deep_symbolize
    end
  end
end
