# frozen_string_literal: true

require "cbor"
require "cose/countersignature_v2"
require "cose/error"
require "cose/security_message"

module COSE
  class Sign1 < SecurityMessage
    include CountersignaturesV2

    CONTEXT = "Signature1"

    attr_reader :payload, :signature

    def self.keyword_arguments_for_initialize(decoded)
      { payload: decoded[0], signature: decoded[1] }
    end

    def self.tag
      18
    end

    def initialize(payload:, signature:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @signature = signature.dup
    end

    def verify(key, external_aad = nil)
      if key.kid == headers.kid
        algorithm.verify(key, signature, verification_data(external_aad))
      else
        raise(COSE::Error, "Non matching kid")
      end
    end

    private

    def default_countersignature_label(_target)
      CountersignatureV2::ZERO_LABEL
    end

    def message_countersignature_target(label: nil, exclude_new: false)
      selected_label = label || CountersignatureV2::ZERO_LABEL
      target_headers = unprotected_headers
      [selected_label, target_headers, nil]
    end

    def serialize_countersignature_target(label, _index, exclude_new: false)
      reject_legacy_countersignatures(unprotected_headers)
      labels_to_remove = exclude_new ? [label] : CountersignatureV2::LABELS
      replacement = unprotected_headers.reject { |key, _| labels_to_remove.include?(key) }
      serialize(unprotected_headers: replacement)
    end

    def emit_countersignature(label, _headers, value)
      replacement = unprotected_headers.merge(label => value)
      serialize(unprotected_headers: replacement)
    end

    def verify_original(resolver, external_aad)
      build_status do
        key = resolve_key(resolver, headers.kid)
        raise(COSE::MissingVerificationKeyError, "Missing verification key for original signature") if key.nil?
        verify(key, external_aad)
      end
    end

    def serialize_remainder(overrides)
      [overrides.fetch(:payload, payload), overrides.fetch(:signature, signature)]
    end

    def verification_data(external_aad = nil)
      CBOR.encode([CONTEXT, serialized_protected_headers, external_aad || ZERO_LENGTH_BIN_STRING, payload])
    end
  end
end
