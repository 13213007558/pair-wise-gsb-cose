# frozen_string_literal: true

require "cbor"
require "cose/countersignature_v2"
require "cose/error"
require "cose/security_message"
require "cose/signature"

module COSE
  class Sign < SecurityMessage
    include CountersignaturesV2

    CONTEXT = "Signature"

    attr_reader :payload, :signatures

    def self.keyword_arguments_for_initialize(decoded)
      {
        payload: decoded[0],
        signatures: decoded[1].map.with_index do |signature, index|
          COSE::Signature.from_array(
            signature,
            signature_index: index
          )
        end
      }
    end

    def self.tag
      98
    end

    def initialize(payload:, signatures:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload.dup
      @signatures = signatures
    end

    def cose_signatures
      signatures
    end

    def verify(key, external_aad = nil)
      signature = signatures.detect { |candidate| candidate.headers.kid == key.kid }

      if signature
        signature.algorithm.verify(key, signature.signature, verification_data(signature, external_aad))
      else
        raise(COSE::Error, "No signature matches key kid")
      end
    end

    private

    def message_countersignature_target(label: nil, exclude_new: false)
      selected_label = label || CountersignatureV2::LABEL
      target_headers = unprotected_headers
      [selected_label, target_headers, nil]
    end

    def default_countersignature_label(target)
      target == :message ? CountersignatureV2::LABEL : CountersignatureV2::ZERO_LABEL
    end

    def signature_countersignature_target(index, label: nil, exclude_new: false)
      signature = signatures.fetch(index)
      selected_label = label || CountersignatureV2::ZERO_LABEL
      target_headers = signature.unprotected_headers
      [selected_label, target_headers, index]
    rescue IndexError
      raise(COSE::Error, "Unknown signature target")
    end

    def countersignature_verification_targets
      targets = [[:message, nil]]
      signatures.each_with_index { |_signature, index| targets << [:signature, index] }
      targets
    end

    def serialize_countersignature_target(label, index, exclude_new: false)
      if index.nil?
        reject_legacy_countersignatures(unprotected_headers)
        replacement_signatures = signatures.map do |candidate|
          [
            candidate.serialized_protected_headers,
            without_v2_countersignatures(candidate.unprotected_headers),
            candidate.signature
          ]
        end
        labels_to_remove = exclude_new ? [label] : CountersignatureV2::LABELS
        replacement_headers = unprotected_headers.reject { |key, _| labels_to_remove.include?(key) }
        serialize(unprotected_headers: replacement_headers, signatures: replacement_signatures)
      else
        _target_label, _target_headers, target_index = signature_countersignature_target(index, label: label)
        signature = signatures.fetch(target_index)
        labels_to_remove = exclude_new ? [label] : CountersignatureV2::LABELS
        replacement = signature.unprotected_headers.reject { |key, _| labels_to_remove.include?(key) }
        signature.serialize(unprotected_headers: replacement, tagged: false)
      end
    end

    def emit_countersignature(label, headers, value)
      if headers.equal?(unprotected_headers)
        serialize(unprotected_headers: unprotected_headers.merge(label => value))
      else
        index = signatures.index { |signature| signature.unprotected_headers.equal?(headers) }
        replacement_signatures = signatures.map.with_index do |signature, candidate_index|
          if candidate_index == index
            [
              signature.serialized_protected_headers,
              signature.unprotected_headers.merge(label => value),
              signature.signature
            ]
          else
            [
              signature.serialized_protected_headers,
              signature.unprotected_headers,
              signature.signature
            ]
          end
        end
        serialize(signatures: replacement_signatures)
      end
    end

    def add_original_signature_results(results, resolver, external_aad)
      results[:original_signatures] = signatures.map do |signature|
        result = build_status do
          key = resolve_key(resolver, signature.headers.kid)
          if key.nil?
            raise(COSE::MissingVerificationKeyError, "Missing verification key for original signature")
          end

          signature.algorithm.verify(
            key,
            signature.signature,
            verification_data(signature, original_external_aad(external_aad, signature.signature_index))
          )
        end
        { index: signature.signature_index, kid: signature.headers.kid, result: result }
      end
      statuses = results[:original_signatures].map { |signature| signature[:result] }
      results[:original] = if statuses.all?(&:valid?)
        VerificationResult.new(status: :valid)
      elsif statuses.any?(&:valid?)
        VerificationResult.new(status: :invalid, error: COSE::Error.new("Not all original signatures verified"))
      else
        VerificationResult.new(status: :missing_key)
      end
    end

    def original_external_aad(external_aad, index)
      return external_aad unless external_aad.is_a?(Hash)

      external_aad[[:signature, index]] || external_aad[:signature]
    end

    def serialize_remainder(overrides)
      signature_items = overrides.fetch(:signatures, signatures)
      serialized_signatures = signature_items.map do |signature|
        next signature if signature.is_a?(Array)

        [signature.serialized_protected_headers, signature.unprotected_headers, signature.signature]
      end
      [overrides.fetch(:payload, payload), serialized_signatures]
    end

    def verification_data(signature, external_aad = nil)
      CBOR.encode([
        CONTEXT,
        serialized_protected_headers,
        signature.serialized_protected_headers,
        external_aad || ZERO_LENGTH_BIN_STRING,
        payload
      ])
    end
  end
end
