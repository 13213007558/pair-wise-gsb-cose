# frozen_string_literal: true

module COSE
  class VerificationResult
    STATUSES = [:valid, :invalid, :missing_key].freeze

    attr_reader :name, :status, :kid, :error, :countersignatures

    def self.valid(name, kid, countersignatures: [])
      new(name: name, status: :valid, kid: kid, countersignatures: countersignatures)
    end

    def self.invalid(name, kid, error, countersignatures: [])
      new(name: name, status: :invalid, kid: kid, error: error, countersignatures: countersignatures)
    end

    def self.missing_key(name, kid, countersignatures: [])
      new(name: name, status: :missing_key, kid: kid, countersignatures: countersignatures)
    end

    def initialize(name:, status:, kid: nil, error: nil, countersignatures: [])
      raise ArgumentError unless STATUSES.include?(status)

      @name = name
      @status = status
      @kid = kid
      @error = error
      @countersignatures = countersignatures
    end

    def valid?
      status == :valid
    end

    def invalid?
      status == :invalid
    end

    def missing_key?
      status == :missing_key
    end
  end
end
