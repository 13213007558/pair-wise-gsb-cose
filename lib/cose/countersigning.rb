# frozen_string_literal: true

require "cose/countersignature_v2"
require "cose/verification_result"

module COSE
  module Countersigning
    LABEL_COUNTERSIGNATURE_V2 = CountersignatureV2::LABEL_COUNTERSIGNATURE_V2
    LABEL_COUNTERSIGNATURE0_V2 = CountersignatureV2::LABEL_COUNTERSIGNATURE0_V2

    private

    def resolve_key(keys, kid)
      key = case keys
            when Hash
              keys[kid]
            when Array
              keys.detect { |candidate| key_kid(candidate) == kid }
            when Proc, Method
              keys.call(kid)
            else
              keys
            end

      return nil if key.nil?
      return nil if key.respond_to?(:kid) && key.kid && kid && key.kid != kid

      key
    end

    def key_kid(key)
      key.respond_to?(:kid) ? key.kid : nil
    end

    def normalize_countersignature_headers(key, protected_headers, unprotected_headers)
      protected_headers = protected_headers.dup
      unprotected_headers = unprotected_headers.dup
      protected_headers[1] ||= key.alg if key.respond_to?(:alg) && key.alg
      unprotected_headers[4] ||= key.kid if key.respond_to?(:kid) && key.kid
      [protected_headers, unprotected_headers]
    end

    def create_countersignature(kind, key, protected_headers, unprotected_headers, input)
      algorithm = COSE::Algorithm.find(protected_headers[1] || (key.respond_to?(:alg) && key.alg))
      algorithm || raise(COSE::Error, "Unsupported countersignature algorithm")

      CountersignatureV2.new(
        kind: kind,
        protected_headers: protected_headers,
        serialized_protected_headers: protected_headers.to_cbor,
        unprotected_headers: unprotected_headers,
        signature: algorithm.sign(key, input)
      )
    end

    def placeholder(kind, protected_headers, unprotected_headers)
      CountersignatureV2.new(
        kind: kind,
        protected_headers: protected_headers,
        serialized_protected_headers: protected_headers.to_cbor,
        unprotected_headers: unprotected_headers,
        signature: SecurityMessage::ZERO_LENGTH_BIN_STRING
      )
    end

    def verify_signature_result(name, kid, key, algorithm_id, signature, data, countersignatures)
      if key.nil?
        return VerificationResult.missing_key(name, kid, countersignatures: countersignatures)
      else
        begin
          algorithm = COSE::Algorithm.find(algorithm_id)
          algorithm || raise(COSE::Error, "Unsupported algorithm")
          algorithm.verify(key, signature, data)
          return VerificationResult.valid(name, kid, countersignatures: countersignatures)
        rescue COSE::Error => error
          return VerificationResult.invalid(name, kid, error, countersignatures: countersignatures)
        end
      end
    end

    def serialize_v2_entries(entries)
      arrays = entries.map(&:to_a)
      arrays.length == 1 ? arrays.first : arrays
    end

    def verify_countersignatures(countersignatures, inputs, keys, path)
      countersignatures.each_with_index.map do |countersignature, index|
        counter_path = path + [index.to_s]
        verify_countersignature(
          countersignature,
          inputs.fetch(key_for(countersignature)),
          keys,
          counter_path
        )
      end
    end

    def verify_countersignature(countersignature, input, keys, path)
      name = path.join("/")
      key = resolve_key(keys, countersignature.headers.kid)
      nested_results = verify_countersignatures(
        countersignature.nested_countersignatures,
        nested_inputs(countersignature, input),
        keys,
        path + ["countersignature"]
      )

      if key.nil?
        return VerificationResult.missing_key(name, countersignature.headers.kid, countersignatures: nested_results)
      end

      begin
        raise(COSE::Error, "Unsupported algorithm") unless COSE::Algorithm.find(countersignature.headers.alg)
        countersignature.verify_data(key, input)
      rescue COSE::Error => error
        return VerificationResult.invalid(
          name,
          countersignature.headers.kid,
          error,
          countersignatures: nested_results
        )
      end

      VerificationResult.valid(name, countersignature.headers.kid, countersignatures: nested_results)
    end

    def nested_inputs(countersignature, input)
      nested_input = countersignature.countersignature_verification_data(input)
      countersignature.nested_countersignatures.each_with_object({}) do |nested, inputs|
        inputs[key_for(nested)] = nested_input
      end
    end

    def key_for(object)
      [object.protected_header_bytes, object.unprotected_headers, object.signature]
    end
  end
end
