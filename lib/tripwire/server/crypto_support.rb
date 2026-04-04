require "openssl"
require "rubygems"

module Tripwire
  module Server
    module CryptoSupport
      MIN_SUPPORTED_RUBY_VERSION = Gem::Version.new("3.3.0")
      UNSUPPORTED_RUNTIME_MESSAGE = "Tripwire Ruby cryptography helpers require Ruby 3.3+ with modern OpenSSL support.".freeze

      module_function

      def supported_runtime?
        return @supported_runtime unless @supported_runtime.nil?

        @supported_runtime = Gem::Version.new(RUBY_VERSION) >= MIN_SUPPORTED_RUBY_VERSION &&
          OpenSSL::PKey.respond_to?(:generate_key) &&
          defined?(OpenSSL::KDF) &&
          OpenSSL::KDF.respond_to?(:hkdf) &&
          aead_auth_data_supported?
      end

      def ensure_supported_runtime!
        return if supported_runtime?

        raise ConfigurationError, UNSUPPORTED_RUNTIME_MESSAGE
      end

      def minimum_supported_ruby_version
        MIN_SUPPORTED_RUBY_VERSION
      end

      def unsupported_runtime_message
        UNSUPPORTED_RUNTIME_MESSAGE
      end

      def aead_auth_data_supported?
        cipher = OpenSSL::Cipher.new("aes-256-gcm")
        cipher.encrypt
        cipher.key = "\x00".b * 32
        cipher.iv = "\x00".b * 12
        cipher.auth_data = "".b
        true
      rescue StandardError
        false
      end
      private_class_method :aead_auth_data_supported?
    end
  end
end
