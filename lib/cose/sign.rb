# frozen_string_literal: true

require "cbor"
require "cose/countersigning"
require "cose/error"
require "cose/security_message"
require "cose/signature"

module COSE
  class Sign < SecurityMessage
    include Countersigning

    CONTEXT = "Signature"

    attr_reader :payload, :signatures

    def self.keyword_arguments_for_initialize(decoded)
      { payload: decoded[0], signatures: decoded[1].map { |s| COSE::Signature.from_array(s) } }
    end

    def self.tag
      98
    end

    def initialize(payload:, signatures:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @signatures = signatures
    end

    def verify(key, external_aad = nil)
      signature = signatures.detect { |s| s.headers.kid == key.kid }

      if signature
        signature.algorithm.verify(key, signature.signature, verification_data(signature, external_aad))
      else
        raise(COSE::Error, "No signature matches key kid")
      end
    end

    def countersign(
      key,
      target:,
      protected_headers: {},
      unprotected_headers: {},
      external_aad: nil
    )
      signature_index, counter_path = target_path(target)
      target_signature = signatures.fetch(signature_index) do
        raise(COSE::Error, "Unknown signature target")
      end
      roots = CountersignatureV2.list(target_signature.unprotected_headers[LABEL_COUNTERSIGNATURE_V2])

      if counter_path.empty?
        roots << create_root_countersignature(
          target_signature,
          key,
          protected_headers,
          unprotected_headers,
          external_aad
        )
      else
        root_index = counter_path.first
        root = roots[root_index] || raise(COSE::Error, "Unknown countersignature target")
        roots[root_index] = append_to_tree(
          root,
          counter_path[1..-1],
          key,
          protected_headers,
          unprotected_headers,
          sign_countersignature_input(root, target_signature, external_aad),
          :root
        )
      end

      rebuilt = signatures.map.with_index do |signature, index|
        next signature unless index == signature_index

        replace_signature_countersignatures(signature, roots)
      end

      self.class.new(
        payload: payload,
        signatures: rebuilt,
        protected_headers: self.protected_headers,
        serialized_protected_headers: protected_header_bytes,
        unprotected_headers: self.unprotected_headers
      )
    end

    def verify_all(keys, external_aad: nil)
      signatures.each_with_index.map do |signature, index|
        signature_aad = external_aad.is_a?(Hash) ? external_aad[index] : external_aad
        input = verification_data(signature, signature_aad)
        counters = CountersignatureV2.list(signature.unprotected_headers[LABEL_COUNTERSIGNATURE_V2])
        inputs = counters.each_with_object({}) do |counter, map|
          map[key_for(counter)] = sign_countersignature_input(counter, signature, signature_aad)
        end
        counter_results = verify_countersignatures(
          counters,
          inputs,
          keys,
          ["signature", index.to_s, "countersignature"]
        )
        verify_signature_result(
          "signature/#{index}",
          signature.headers.kid,
          resolve_key(keys, signature.headers.kid),
          signature.headers.alg,
          signature.signature,
          input,
          counter_results
        )
      end
    end

    def countersignatures_v2(signature_index)
      signatures.fetch(signature_index) do
        raise(COSE::Error, "Unknown signature target")
      end.countersignatures_v2
    end

    private

    def to_a
      [protected_header_bytes, unprotected_headers, payload, signatures.map(&:serialize)]
    end

    def verification_data(signature, external_aad = nil)
      CBOR.encode(
        [
          CONTEXT,
          protected_header_bytes,
          signature.protected_header_bytes,
          external_aad || ZERO_LENGTH_BIN_STRING,
          payload
        ]
      )
    end

    def target_path(target)
      path = Array(target).map(&:to_i)
      raise(COSE::Error, "Unknown signature target") if path.empty? || path.any?(&:negative?)

      [path.first, path[1..-1]]
    end

    def create_root_countersignature(target_signature, key, protected_headers, unprotected_headers, external_aad)
      protected_headers, unprotected_headers =
        normalize_countersignature_headers(key, protected_headers, unprotected_headers)
      temp = placeholder(:signature, protected_headers, unprotected_headers)
      input = sign_countersignature_input(temp, target_signature, external_aad)
      create_countersignature(:signature, key, protected_headers, unprotected_headers, input)
    end

    def sign_countersignature_input(counter, target_signature, external_aad)
      counter.sign_verification_data(
        protected_header_bytes,
        target_signature.protected_header_bytes,
        external_aad,
        payload,
        target_signature.signature
      )
    end

    def append_to_tree(counter, path, key, protected_headers, unprotected_headers, parent_input, parent_kind)
      if path.empty?
        add_nested_countersignature(counter, key, protected_headers, unprotected_headers, parent_input, parent_kind)
      else
        index = path.first
        nested = counter.nested_countersignatures.fetch(index)
        child_input =
          if parent_kind == :root
            counter.countersignature_verification_data(parent_input)
          else
            parent_input
          end
        updated = append_to_tree(
          nested,
          path[1..-1],
          key,
          protected_headers,
          unprotected_headers,
          child_input,
          :counter
        )
        replace_nested_countersignatures(
          counter,
          counter.nested_countersignatures.map.with_index do |entry, entry_index|
            entry_index == index ? updated : entry
          end
        )
      end
    end

    def add_nested_countersignature(counter, key, protected_headers, unprotected_headers, parent_input, parent_kind)
      protected_headers, unprotected_headers =
        normalize_countersignature_headers(key, protected_headers, unprotected_headers)
      target_input =
        if parent_kind == :root
          counter.countersignature_verification_data(parent_input)
        else
          parent_input
        end
      nested = create_countersignature(:signature, key, protected_headers, unprotected_headers, target_input)
      replace_nested_countersignatures(counter, counter.nested_countersignatures + [nested])
    end

    def replace_nested_countersignatures(counter, nested)
      CountersignatureV2.new(
        kind: :signature,
        protected_headers: counter.protected_headers,
        serialized_protected_headers: counter.protected_header_bytes,
        unprotected_headers: counter.unprotected_headers.merge(
          LABEL_COUNTERSIGNATURE_V2 => serialize_v2_entries(nested)
        ),
        signature: counter.signature
      ).tap { |replacement| replacement.set_nested_countersignatures(nested) }
    end

    def replace_signature_countersignatures(signature, counters)
      COSE::Signature.new(
        protected_headers: signature.protected_headers,
        serialized_protected_headers: signature.protected_header_bytes,
        unprotected_headers: signature.unprotected_headers.merge(
          LABEL_COUNTERSIGNATURE_V2 => serialize_v2_entries(counters)
        ),
        signature: signature.signature
      )
    end
  end
end
