# frozen_string_literal: true

require "cose/algorithm/base"
require "cose/error"

module COSE
  module Algorithm
    class SignatureAlgorithm < Base
      def verify(key, signature, verification_data)
        compatible_key?(key) || raise(COSE::Error, "Incompatible key for signature verification")
        valid_signature?(key, signature, verification_data) || raise(COSE::Error, "Signature verification failed")
      end

      def sign(key, verification_data)
        compatible_key?(key) || raise(COSE::Error, "Incompatible key for signing")

        pkey = to_pkey(key)
        signature = sign_signature(pkey, verification_data)
        format_signature(pkey, signature)
      end

      def compatible_key?(key)
        valid_key?(key) && to_pkey(key)
      rescue COSE::Error
        false
      end

      private

      def valid_signature?(key, signature, verification_data)
        signature_algorithm = signature_algorithm_class.new(**signature_algorithm_parameters)
        signature_algorithm.verify_key = to_pkey(key)

        begin
          signature_algorithm.verify(signature, verification_data)
        rescue OpenSSL::SignatureAlgorithm::Error
          false
        end
      end

      def signature_algorithm_parameters
        { hash_function: hash_function }
      end

      def to_cose_key(key)
        case key
        when COSE::Key::Base
          key
        when OpenSSL::PKey::PKey
          COSE::Key.from_pkey(key)
        else
          raise(COSE::Error, "Don't know how to transform #{key.class} to COSE::Key")
        end
      end

      def sign_signature(pkey, verification_data)
        pkey.sign(hash_function, verification_data)
      end

      def format_signature(_pkey, signature)
        signature
      end

      def signature_algorithm_class
        raise NotImplementedError
      end

      def valid_key?(_key)
        raise NotImplementedError
      end

      def to_pkey(_key)
        raise NotImplementedError
      end
    end
  end
end
