# frozen_string_literal: true

require "cbor"
require "cose/algorithm"
require "cose/cbor_safe"
require "cose/error"
require "cose/security_message/headers"

module COSE
  class SecurityMessage
    ZERO_LENGTH_BIN_STRING = "".b

    attr_reader :protected_headers, :unprotected_headers, :serialized_protected_headers

    def self.deserialize(cbor)
      decoded = CborSafe.decode(cbor)
      tagged = decoded.is_a?(CBOR::Tagged)

      if tagged
        if respond_to?(:tag) && tag != decoded.tag
          raise(COSE::Error, "Invalid CBOR tag")
        end

        decoded = decoded.value
      end

      from_array(decoded, tagged: tagged)
    rescue ArgumentError, TypeError, CBOR::MalformedFormatError
      raise(COSE::Error, "Malformed COSE message")
    end

    def self.from_array(array, tagged: false, **options)
      new(
        protected_headers: deserialize_headers(array[0]),
        serialized_protected_headers: array[0]&.dup,
        unprotected_headers: deep_dup_decoded(array[1]),
        tagged: tagged,
        **options,
        **keyword_arguments_for_initialize(array[2..-1] || [])
      )
    end

    def self.deserialize_headers(data)
      if data == ZERO_LENGTH_BIN_STRING
        {}
      else
        CborSafe.decode(data)
      end
    end

    def initialize(protected_headers:, unprotected_headers:, serialized_protected_headers: nil, tagged: false)
      @protected_headers = protected_headers
      @unprotected_headers = unprotected_headers
      @serialized_protected_headers = (serialized_protected_headers || serialized_map(protected_headers)).dup
      @tagged = tagged
    end

    def algorithm
      @algorithm ||= COSE::Algorithm.find(headers.alg) || raise(COSE::Error, "Unsupported algorithm '#{headers.alg}'")
    end

    def headers
      @headers ||= Headers.new(protected_headers, unprotected_headers)
    end

    def serialize(protected_headers: nil, unprotected_headers: nil,
                   serialized_protected_headers: nil, tagged: nil, **overrides)
      protected_headers ||= @protected_headers
      unprotected_headers ||= @unprotected_headers
      serialized_protected_headers ||= @serialized_protected_headers
      tagged = @tagged if tagged.nil?
      unprotected_headers = deep_dup_bstrings(unprotected_headers)
      overrides = deep_dup_bstrings(overrides)
      array = serialize_array(
        protected_headers: protected_headers,
        unprotected_headers: unprotected_headers,
        serialized_protected_headers: (serialized_protected_headers || @serialized_protected_headers).dup,
        overrides: overrides
      )
      message = CBOR.encode(array)

      if tagged
        CBOR::Tagged.new(self.class.tag, array).to_cbor
      else
        message
      end
    end

    private

    def serialize_array(protected_headers:, unprotected_headers:, serialized_protected_headers:, overrides:)
      [
        (serialized_protected_headers || serialized_map(protected_headers)).dup,
        unprotected_headers,
        *serialize_remainder(overrides)
      ]
    end

    def serialize_remainder(_overrides)
      raise NotImplementedError
    end

    def deep_dup_bstrings(value)
      case value
      when String
        String.new("", encoding: Encoding::BINARY).b.replace(value.b)
      when Hash
        value.each_with_object({}) { |(key, item), duplicate| duplicate[key] = deep_dup_bstrings(item) }
      when Array
        value.map { |item| deep_dup_bstrings(item) }
      else
        value
      end
    end

    class << self
      private

      def deep_dup_decoded(value)
        case value
        when String
          String.new("", encoding: Encoding::BINARY).b.replace(value.b)
        when Hash
          value.each_with_object({}) do |(key, item), duplicate|
            duplicate[key] = deep_dup_decoded(item)
          end
        when Array
          value.map { |item| deep_dup_decoded(item) }
        else
          value
        end
      end
    end

    def serialized_map(map)
      if map && !map.empty?
        map.to_cbor
      else
        zero_length_bin_string
      end
    end

    def zero_length_bin_string
      ZERO_LENGTH_BIN_STRING
    end
  end
end
