module Tripwire
  module Server
    class ConfigurationError < StandardError; end

    class TokenVerificationError < StandardError; end

    class ApiError < StandardError
      attr_reader :status, :code, :request_id, :field_errors, :docs_url, :body

      def initialize(status:, code:, message:, request_id: nil, field_errors: [], docs_url: nil, body: nil)
        super(message)
        @status = status
        @code = code
        @request_id = request_id
        @field_errors = field_errors
        @docs_url = docs_url
        @body = body
      end
    end
  end
end
