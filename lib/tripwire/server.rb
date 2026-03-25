require_relative "server/version"
require_relative "server/errors"
require_relative "server/types"
require_relative "server/sealed_token"
require_relative "server/client"

module Tripwire
  module Server
    module_function

    def verify_tripwire_token(sealed_token, secret_key = nil)
      SealedToken.verify_tripwire_token(sealed_token, secret_key)
    end

    def safe_verify_tripwire_token(sealed_token, secret_key = nil)
      SealedToken.safe_verify_tripwire_token(sealed_token, secret_key)
    end
  end
end
