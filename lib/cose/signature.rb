# frozen_string_literal: true

require "cose/security_message"

module COSE
  class Signature < SecurityMessage
    attr_reader :signature

    def self.keyword_arguments_for_initialize(decoded)
      { signature: decoded[0] }
    end

    def initialize(signature:, signature_index: nil, **keyword_arguments)
      super(**keyword_arguments)

      @signature = signature.dup
      @signature_index = signature_index
    end

    def signature_index
      @signature_index || 0
    end

    private

    def serialize_remainder(overrides)
      [overrides.fetch(:signature, signature)]
    end
  end
end
