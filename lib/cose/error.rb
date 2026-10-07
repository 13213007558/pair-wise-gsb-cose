# frozen_string_literal: true

module COSE
  class Error < StandardError; end
  class MissingVerificationKeyError < Error
    def initialize(message = "Missing verification key")
      super
    end
  end
end
