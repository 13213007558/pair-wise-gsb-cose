# frozen_string_literal: true

require "cose/countersignature_v2"
require "cose/security_message"

module COSE
  class Signature < SecurityMessage
    attr_reader :signature

    def self.keyword_arguments_for_initialize(decoded)
      { signature: decoded[0] }
    end

    def initialize(signature:, **keyword_arguments)
      super(**keyword_arguments)

      @signature = signature
    end

    def countersignatures_v2
      COSE::CountersignatureV2.list(
        unprotected_headers[COSE::CountersignatureV2::LABEL_COUNTERSIGNATURE_V2]
      )
    end

    private

    def to_a
      [protected_header_bytes, unprotected_headers, signature]
    end
  end
end
