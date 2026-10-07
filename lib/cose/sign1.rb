# frozen_string_literal: true

require "cbor"
require "cose/countersigning"
require "cose/error"
require "cose/security_message"

module COSE
  class Sign1 < SecurityMessage
    include Countersigning

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
      @signature = signature
    end

    def verify(key, external_aad = nil)
      if key.kid == headers.kid
        algorithm.verify(key, signature, verification_data(external_aad))
      else
        raise(COSE::Error, "Non matching kid")
      end
    end

    def countersign(
      key,
      target: nil,
      protected_headers: {},
      unprotected_headers: {},
      external_aad: nil
    )
      path = Array(target).map(&:to_i)
      unless path.all? { |index| index >= 0 }
        raise(COSE::Error, "Unknown countersignature target")
      end

      root = message_countersignatures_v2.first
      if root.nil?
        raise(COSE::Error, "Unknown countersignature target") if path.any?

        root = create_root_countersignature(key, protected_headers, unprotected_headers, external_aad)
      elsif path.empty?
        raise(COSE::Error, "Message already has a Countersignature0V2")
      end
      root = append_to_tree(root, path, key, protected_headers, unprotected_headers, external_aad) if path.any?

      self.class.new(
        payload: payload,
        signature: signature,
        protected_headers: self.protected_headers,
        serialized_protected_headers: protected_header_bytes,
        unprotected_headers: self.unprotected_headers.merge(LABEL_COUNTERSIGNATURE0_V2 => root.to_a)
      )
    end

    def message_countersignatures_v2
      COSE::CountersignatureV2.list(unprotected_headers[LABEL_COUNTERSIGNATURE0_V2])
    end

    def verify_all(keys, external_aad: nil)
      root_data = verification_data(external_aad)
      counters = message_countersignatures_v2
      inputs = counters.each_with_object({}) do |counter, map|
        map[key_for(counter)] =
          counter.sign1_verification_data(protected_header_bytes, external_aad, payload, signature)
      end
      counter_results = verify_countersignatures(counters, inputs, keys, ["countersignature"])

      [
        verify_signature_result(
          "signature",
          headers.kid,
          resolve_key(keys, headers.kid),
          headers.alg,
          signature,
          root_data,
          counter_results
        )
      ]
    end

    private

    def to_a
      [protected_header_bytes, unprotected_headers, payload, signature]
    end

    def verification_data(external_aad = nil)
      CBOR.encode([CONTEXT, protected_header_bytes, external_aad || ZERO_LENGTH_BIN_STRING, payload])
    end

    def create_root_countersignature(key, protected_headers, unprotected_headers, external_aad)
      protected_headers, unprotected_headers =
        normalize_countersignature_headers(key, protected_headers, unprotected_headers)
      temp = placeholder(:sign1, protected_headers, unprotected_headers)
      input = temp.sign1_verification_data(protected_header_bytes, external_aad, payload, signature)
      create_countersignature(:sign1, key, protected_headers, unprotected_headers, input)
    end

    def append_to_tree(counter, path, key, protected_headers, unprotected_headers, external_aad)
      index = path.first
      raise(COSE::Error, "Unknown countersignature target") unless index.zero?

      counter_input =
        if counter.sign1?
          counter.sign1_verification_data(protected_header_bytes, external_aad, payload, signature)
        else
          counter.countersignature_verification_data(verification_data(external_aad))
        end

      append_or_descend(
        counter,
        path,
        key,
        protected_headers,
        unprotected_headers,
        counter_input,
        counter.sign1? ? :root : :counter
      )
    end

    def append_or_descend(counter, path, key, protected_headers, unprotected_headers, parent_input, parent_kind)
      if path.length == 1
        target_content = counter.countersignature_verification_data(parent_input)
        add_nested_countersignature(counter, key, protected_headers, unprotected_headers, target_content, parent_kind)
      else
        nested = counter.nested_countersignatures.fetch(path.first)
        next_input = parent_kind == :root ? counter.countersignature_verification_data(parent_input) : parent_input
        updated = append_or_descend(
          nested,
          path[1..-1],
          key,
          protected_headers,
          unprotected_headers,
          next_input,
          :counter
        )
        replace_nested_countersignature(counter, counter.nested_countersignatures.map.with_index do |entry, index|
          index == path.first ? updated : entry
        end)
      end
    end

    def add_nested_countersignature(counter, key, protected_headers, unprotected_headers, target_content, parent_kind)
      protected_headers, unprotected_headers =
        normalize_countersignature_headers(key, protected_headers, unprotected_headers)
      input = target_content
      nested = create_countersignature(:signature, key, protected_headers, unprotected_headers, input)
      replace_nested_countersignature(counter, counter.nested_countersignatures + [nested])
    end

    def replace_nested_countersignature(counter, nested)
      CountersignatureV2.new(
        kind: counter.sign1? ? :sign1 : :signature,
        protected_headers: counter.protected_headers,
        serialized_protected_headers: counter.protected_header_bytes,
        unprotected_headers: counter.unprotected_headers.merge(
          LABEL_COUNTERSIGNATURE_V2 => serialize_v2_entries(nested)
        ),
        signature: counter.signature
      ).tap { |replacement| replacement.instance_variable_set(:@nested_countersignatures, nested) }
    end
  end
end
