# frozen_string_literal: true

require "cbor"
require "cose/error"
require "cose/security_message"

module COSE
  class CountersignatureV2 < SecurityMessage
    LABEL_COUNTERSIGNATURE_V2 = 19
    LABEL_COUNTERSIGNATURE0_V2 = 20
    LEGACY_LABEL_COUNTERSIGNATURE = 11
    LEGACY_LABEL_COUNTERSIGNATURE0 = 12

    CONTEXT_COUNTERSIGNATURE_V2 = "CounterSignatureV2"
    CONTEXT_COUNTERSIGNATURE0_V2 = "CounterSignature0V2"

    attr_reader :signature

    def self.from_array(array)
      unless array.is_a?(Array)
        raise(COSE::Error, "Invalid CountersignatureV2")
      end

      case array.length
      when 3
        new(
          kind: :signature,
          protected_headers: deserialize_headers(array[0]),
          serialized_protected_headers: array[0],
          unprotected_headers: array[1],
          signature: array[2]
        )
      when 4
        unless array[2].nil?
          raise(COSE::Error, "Invalid CountersignatureV2")
        end

        new(
          kind: :sign1,
          protected_headers: deserialize_headers(array[0]),
          serialized_protected_headers: array[0],
          unprotected_headers: array[1],
          signature: array[3]
        )
      else
        raise(COSE::Error, "Invalid CountersignatureV2")
      end
    end

    def self.list(value)
      return [] if value.nil?

      entries =
        if value.is_a?(Array) && value.first.is_a?(Array)
          value
        elsif value.is_a?(Array)
          [value]
        else
          raise(COSE::Error, "Invalid CountersignatureV2")
        end

      entries.map { |entry| from_array(entry) }
    end

    def initialize(kind:, protected_headers:, unprotected_headers:, signature:, serialized_protected_headers: nil)
      @kind = kind
      @signature = signature

      super(
        protected_headers: protected_headers,
        unprotected_headers: unprotected_headers,
        serialized_protected_headers: serialized_protected_headers
      )
    end

    def signature?
      @kind == :signature
    end

    def sign1?
      @kind == :sign1
    end

    def nested_countersignatures
      @nested_countersignatures ||= CountersignatureV2.list(unprotected_headers[LABEL_COUNTERSIGNATURE_V2])
    end

    def set_nested_countersignatures(countersignatures)
      @nested_countersignatures = countersignatures
    end

    def target
      sign1? ? :message : :signature
    end

    def sign1_verification_data(target_protected_headers, external_aad, payload, target_signature)
      CBOR.encode(
        [
          CONTEXT_COUNTERSIGNATURE0_V2,
          protected_header_bytes,
          target_protected_headers,
          external_aad || ZERO_LENGTH_BIN_STRING,
          payload,
          target_signature
        ]
      )
    end

    def sign_verification_data(
      body_protected_headers,
      signer_protected_headers,
      external_aad,
      payload,
      target_signature
    )
      CBOR.encode(
        [
          CONTEXT_COUNTERSIGNATURE_V2,
          protected_header_bytes,
          body_protected_headers,
          signer_protected_headers,
          external_aad || ZERO_LENGTH_BIN_STRING,
          payload,
          target_signature
        ]
      )
    end

    def countersignature_verification_data(target_verification_data)
      CBOR.encode(
        [
          CONTEXT_COUNTERSIGNATURE_V2,
          protected_header_bytes,
          ZERO_LENGTH_BIN_STRING,
          target_verification_data,
          signature
        ]
      )
    end

    def verify_data(key, verification_data)
      algorithm.verify(key, signature, verification_data)
    end

    def to_a
      if sign1?
        [protected_header_bytes, unprotected_headers, nil, signature]
      else
        [protected_header_bytes, unprotected_headers, signature]
      end
    end
  end
end
