# frozen_string_literal: true

require "cose/algorithm/signature_algorithm"
require "cose/error"
require "cose/key/curve"
require "cose/key/ec2"
require "openssl"
require "openssl/signature_algorithm/ecdsa"

module COSE
  module Algorithm
    class ECDSA < SignatureAlgorithm
      attr_reader :hash_function, :curve

      def initialize(*args, hash_function:, curve_name:)
        super(*args)

        @hash_function = hash_function
        @curve = COSE::Key::Curve.by_name(curve_name) || raise("Couldn't find curve with name='#{curve_name}'")
      end

      private

      def sign_signature(pkey, verification_data)
        pkey.sign(hash_function, verification_data)
      end

      def format_signature(pkey, signature)
        asn1 = OpenSSL::ASN1.decode(signature)
        length = (pkey.group.degree + 7) / 8
        asn1.value.map { |integer| integer.value.to_s(2).rjust(length, "\0") }.join
      end

      def valid_key?(key)
        cose_key = to_cose_key(key)

        cose_key.is_a?(COSE::Key::EC2) && (!cose_key.alg || cose_key.alg == id)
      end

      def signature_algorithm_class
        OpenSSL::SignatureAlgorithm::ECDSA
      end

      def signature_algorithm_parameters
        if curve
          super.merge(curve: curve.pkey_name)
        else
          super
        end
      end

      def to_pkey(key)
        case key
        when COSE::Key::EC2
          key.to_pkey
        when OpenSSL::PKey::EC
          key
        else
          raise(COSE::Error, "Incompatible key for algorithm")
        end
      end
    end
  end
end
