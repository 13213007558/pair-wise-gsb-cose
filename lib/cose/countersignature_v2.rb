# frozen_string_literal: true

require "cbor"
require "cose/error"
require "cose/security_message"

module COSE
  VerificationResult = Struct.new(:status, :error, keyword_init: true) do
    def valid?
      status == :valid
    end

    def missing_key?
      status == :missing_key
    end

    def invalid?
      status == :invalid
    end
  end

  CountersignatureV2VerificationResult = Struct.new(
    :target, :index, :signature_index, :label, :kid, :result, :nested, keyword_init: true
  ) do
    def valid?
      result.valid?
    end

    def missing_key?
      result.missing_key?
    end

    def invalid?
      result.invalid?
    end
  end

  class CountersignatureV2
    LEGACY_LABEL = 11
    LEGACY_ZERO_LABEL = 12
    LABEL = 19
    ZERO_LABEL = 20
    LABELS = [LABEL, ZERO_LABEL].freeze
    LEGACY_LABELS = [LEGACY_LABEL, LEGACY_ZERO_LABEL].freeze

    attr_reader :label, :message, :target, :index, :external_aad

    def self.decode(label, value, target:, index: nil, external_aad: nil)
      raise(COSE::Error, "Unsupported countersignature label") unless LABELS.include?(label)

      expected_class = label == LABEL ? COSE::Sign : COSE::Sign1
      message = expected_class.deserialize(value)
      new(
        label: label,
        message: message,
        target: target,
        index: index,
        external_aad: external_aad
      )
    end

    def initialize(label:, message:, target:, index: nil, external_aad: nil)
      @label = label
      @message = message
      @target = target
      @index = index
      @external_aad = external_aad
    end

    def kid
      message.headers.kid || countersigner_signatures.first&.headers&.kid
    end

    def countersigner_signatures
      message.is_a?(COSE::Sign1) ? [message] : message.cose_signatures
    end

    def verify(key, target_bytes, signature_index = 0)
      if label == ZERO_LABEL
        raise(COSE::Error, "Countersignature index out of range") unless signature_index.zero?

        message.verify(key, external_aad)
        raise(COSE::Error, "Countersignature target mismatch") unless message.payload == target_bytes
      else
        signature = countersigner_signatures.fetch(signature_index)
        raise(COSE::Error, "Countersignature target mismatch") unless message.payload == target_bytes
        raise(COSE::Error, "Non matching kid") unless signature.headers.kid.nil? || signature.headers.kid == key.kid

        signature.algorithm.verify(key, signature.signature, verification_data(signature, target_bytes))
      end
    rescue IndexError
      raise(COSE::Error, "Countersignature index out of range")
    end

    private

    def verification_data(signature, target_bytes)
      CBOR.encode([
        COSE::Sign::CONTEXT,
        message.serialized_protected_headers,
        signature.serialized_protected_headers,
        external_aad || SecurityMessage::ZERO_LENGTH_BIN_STRING,
        target_bytes
      ])
    end
  end

  module CountersignaturesV2
    def add_countersignature0_v2(key, **options)
      add_countersignature_v2(key, **options, multiple: false)
    end

    def add_countersignature_v2(key, external_aad: nil, target: :message,
                                protected_headers: {}, unprotected_headers: {}, multiple: false)
      cose_key = to_cose_signing_key(key)
      algorithm = COSE::Algorithm.find(cose_key.alg) || raise(COSE::Error, "Unsupported signing algorithm")
      target_label = target_countersignature_label(target, multiple)
      label, headers, index = countersignature_target(target, label: target_label)
      target_bytes = serialize_countersignature_target(label, index, exclude_new: true)
      if target.is_a?(Integer)
        target_bytes = remove_target_countersignature_header(target_bytes, label, index)
      end
      existing = existing_countersignatures(headers, target, index, external_aad)
      value = countersignature_value(
        multiple: label == CountersignatureV2::LABEL,
        key: cose_key,
        algorithm: algorithm,
        target_bytes: target_bytes,
        external_aad: external_aad,
        protected_headers: protected_headers,
        unprotected_headers: unprotected_headers,
        existing: existing,
        multiple_requested: multiple
      )

      emit_countersignature(label, headers, value)
    end

    def countersignatures_v2(target: :message, external_aad: nil)
      countersignature_headers_for_target(target).flat_map do |label, headers, index|
        next [] unless headers.key?(label)

        [CountersignatureV2.decode(
          label,
          headers[label],
          target: index.nil? ? :message : :signature,
          index: index,
          external_aad: external_aad
        )]
      end
    end

    def countersignature_v2(**options)
      countersignatures_v2(**options).select { |counter| counter.label == CountersignatureV2::LABEL }
    end

    def countersignature0_v2(**options)
      countersignatures_v2(**options).select { |counter| counter.label == CountersignatureV2::ZERO_LABEL }
    end

    def verify_with_countersignatures_v2(keys = nil, external_aad = nil, counter_external_aads = nil, **key_options)
      if keys.nil?
        external_aad = key_options.delete(:external_aad)
        counter_external_aads = key_options.delete(:counter_external_aads)
        keys = key_options
      else
        external_aad = key_options.delete(:external_aad) if key_options.key?(:external_aad)
        counter_external_aads = key_options.delete(:counter_external_aads)
      end
      resolver = key_resolver(keys)
      results = { original: nil, countersignatures: [] }
      add_original_signature_results(results, resolver, external_aad)
      results[:original] ||= verify_original(resolver, external_aad)
      countersignature_verification_targets.each do |(target, index)|
        countersignature_headers_for_target(index.nil? ? :message : index).each do |label, headers|
          next unless headers.key?(label)

          target_bytes = serialize_countersignature_target(label, index)
      counter = CountersignatureV2.decode(
        label,
        headers[label],
        target: target,
        index: index,
        external_aad: external_aad_for(counter_external_aads, target, index)
      )
          counter.countersigner_signatures.each_with_index do |_countersignature, signature_index|
            results[:countersignatures] <<
              verify_countersignature(
                counter,
                target_bytes,
                resolver,
                signature_index,
                nested_external_aads(counter_external_aads, target, index)
              )
          end
        end
      end

      results
    end

    private

    def countersignature_verification_targets
      [[:message, nil]]
    end

    def add_original_signature_results(_results, _resolver, _external_aad)
    end

    def countersignature_target(target, label: nil, exclude_new: false)
      case target
      when :message
        message_countersignature_target(label: label, exclude_new: exclude_new)
      when Integer
        signature_countersignature_target(target, label: label, exclude_new: exclude_new)
      else
        raise(COSE::Error, "Unknown countersignature target")
      end
    end

    def message_countersignature_target(label: nil, exclude_new: false)
      raise NotImplementedError
    end

    def signature_countersignature_target(_index, label: nil, exclude_new: false)
      raise(COSE::Error, "Signature countersignatures are only supported on COSE_Sign")
    end

    def countersignature_headers_for_target(target)
      if target == :message
        CountersignatureV2::LABELS.map do |label|
          message_countersignature_target(label: label)
        end
      else
        CountersignatureV2::LABELS.map do |label|
          signature_countersignature_target(target, label: label)
        end
      end
    end

    def target_countersignature_label(target, multiple)
      multiple ? CountersignatureV2::LABEL : default_countersignature_label(target)
    end

    def default_countersignature_label(_target)
      CountersignatureV2::ZERO_LABEL
    end

    def without_v2_countersignatures(headers)
      headers.reject { |label, _| CountersignatureV2::LABELS.include?(label) }
    end

    def reject_legacy_countersignatures(headers)
      legacy = headers.keys.detect { |label| CountersignatureV2::LEGACY_LABELS.include?(label) }
      if legacy
        raise(COSE::Error, "Legacy countersignature label #{legacy} cannot be interpreted as CountersignatureV2")
      end
    end

    def existing_countersignatures(headers, target, index, external_aad)
      reject_legacy_countersignatures(headers)
      existing_label = headers.key?(CountersignatureV2::LABEL) ? CountersignatureV2::LABEL : CountersignatureV2::ZERO_LABEL
      return [] unless headers.key?(existing_label)

      [CountersignatureV2.decode(
        existing_label,
        headers[existing_label],
        target: index.nil? ? :message : :signature,
        index: index,
        external_aad: external_aad
      )]
    end

    def countersignature_value(multiple:, key:, algorithm:, target_bytes:, external_aad:,
                              protected_headers:, unprotected_headers:, existing:, multiple_requested:)
      countersigner_protected = protected_headers.merge(
        SecurityMessage::Headers::HEADER_LABEL_ALG => algorithm.id
      )
      serialized_countersigner_protected_headers = CBOR.encode(countersigner_protected)
      countersigner_unprotected = unprotected_headers.dup
      countersigner_unprotected[SecurityMessage::Headers::HEADER_LABEL_KID] = key.kid if key.kid

      if multiple
        entries = existing.flat_map(&:countersigner_signatures)
        wrapper_protected = {}
        entries << sign_counter_signature(
          algorithm, key, CountersignatureV2::LABEL, countersigner_protected,
          countersigner_unprotected, target_bytes, external_aad, wrapper_protected
        )
        COSE::Sign.new(
          protected_headers: wrapper_protected,
          unprotected_headers: {},
          payload: target_bytes,
          signatures: entries
        ).serialize(tagged: false)
      else
        if existing.any? { |counter| counter.label == CountersignatureV2::LABEL } || multiple_requested
          raise(COSE::Error, "Cannot append CountersignatureV2 to Countersignature0V2")
        end

        signature = algorithm.sign(
          key,
          CBOR.encode([
            COSE::Sign1::CONTEXT,
            serialized_countersigner_protected_headers.dup,
            external_aad || SecurityMessage::ZERO_LENGTH_BIN_STRING,
            stable_binary(target_bytes)
          ])
        )
        COSE::Sign1.new(
          protected_headers: countersigner_protected,
          serialized_protected_headers: serialized_countersigner_protected_headers,
          unprotected_headers: countersigner_unprotected,
          payload: target_bytes,
          signature: signature
        ).serialize(tagged: false)
      end
    end

    def sign_counter_signature(algorithm, key, _label, protected_headers, unprotected_headers,
                               target_bytes, external_aad, wrapper_protected)
      signature = algorithm.sign(
        key,
        CBOR.encode([
          COSE::Sign::CONTEXT,
          SecurityMessage::ZERO_LENGTH_BIN_STRING,
          CBOR.encode(protected_headers).dup,
          external_aad || SecurityMessage::ZERO_LENGTH_BIN_STRING,
          stable_binary(target_bytes)
        ])
      )
      COSE::Signature.new(
        protected_headers: protected_headers,
        unprotected_headers: unprotected_headers,
        signature: signature
      )
    end

    def to_cose_signing_key(key)
      cose_key = key.is_a?(COSE::Key::Base) ? key : COSE::Key.from_pkey(key)
      cose_key.alg || raise(COSE::Error, "Signing key must include alg")
      cose_key
    end

    def stable_binary(value)
      String.new("", encoding: Encoding::BINARY).b.replace(value.b)
    end

    def remove_target_countersignature_header(value, label, index)
      decoded = COSE::CborSafe.decode(value)
      return value unless decoded.is_a?(Array)

      decoded[1] = decoded[1].reject { |key, _| key == label }
      decoded[0] = CBOR.encode(decoded[0]) unless decoded[0].is_a?(String)
      if decoded[3].is_a?(Array)
        decoded[3] = decoded[3].each_with_index.map do |signature, signature_index|
          next signature unless signature_index == index

          signature[0] = CBOR.encode(signature[0]) unless signature[0].is_a?(String)
          signature[1] = signature[1].reject { |key, _| key == label }
          signature
        end
      end
      CBOR.encode(decoded)
    end

    def key_resolver(keys)
      case keys
      when Hash
        ->(kid) { keys[kid] }
      when Array
        ->(kid) { keys.detect { |key| to_cose_verification_key(key).kid == kid } }
      when Proc
        keys
      else
        key = keys
        ->(kid) { key if to_cose_verification_key(key).kid == kid }
      end
    end

    def to_cose_verification_key(key)
      key.is_a?(COSE::Key::Base) ? key : COSE::Key.from_pkey(key)
    rescue COSE::Error
      key
    end

    def resolve_key(resolver, kid)
      key = resolver.call(kid)
      return if key.nil?

      key.is_a?(COSE::Key::Base) ? key : COSE::Key.from_pkey(key)
    rescue COSE::Error
      raise(COSE::Error, "Unsupported verification key")
    end

    def build_status
      yield
      VerificationResult.new(status: :valid)
    rescue COSE::MissingVerificationKeyError => error
      VerificationResult.new(status: :missing_key, error: error)
    rescue COSE::Error => error
      VerificationResult.new(status: :invalid, error: error)
    end

    def verify_countersignature(counter, target_bytes, resolver, signature_index, counter_external_aads = nil)
      result = build_status do
        countersignature = counter.countersigner_signatures.fetch(signature_index)
        kid = countersignature.headers.kid || counter.message.headers.kid
        key = resolve_key(resolver, kid)
        raise(COSE::MissingVerificationKeyError, "Missing verification key for countersigner") if key.nil?
        counter.verify(key, target_bytes, signature_index)
      end
      countersignature = counter.countersigner_signatures[signature_index]
      CountersignatureV2VerificationResult.new(
        target: counter.target,
        index: counter.index,
        signature_index: signature_index,
        label: counter.label,
        kid: countersignature&.headers&.kid,
        result: result,
        nested: nested_countersignature_results(counter, resolver, counter_external_aads)
      )
    end

    def nested_countersignature_results(counter, resolver, counter_external_aads)
      nested = counter.message.verify_with_countersignatures_v2(
        resolver,
        external_aad: nil,
        counter_external_aads: counter_external_aads
      )
      nested[:countersignatures]
    rescue COSE::Error => error
      [CountersignatureV2VerificationResult.new(
        target: :nested,
        index: nil,
        signature_index: nil,
        label: nil,
        kid: nil,
        result: VerificationResult.new(status: :invalid, error: error),
        nested: []
      )]
    end

    def external_aad_for(aads, target, index)
      return unless aads

      aads[[target, index]] || aads[target]
    end

    def nested_external_aads(aads, target, index)
      return unless aads

      prefix = [target, index]
      aads.each_with_object({}) do |(key, value), nested|
        next unless key.is_a?(Array) && key.first(2) == prefix

        nested[key[2..-1]] = value
      end
    end
  end
end
