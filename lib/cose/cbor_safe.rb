# frozen_string_literal: true

require "cbor"

module COSE
  module CborSafe
    module_function

    def decode(data)
      value, _remaining = decode_value(data.b)
      value
    end

    def decode_value(data)
      byte = data.bytes.first
      major = byte >> 5
      argument = byte & 0x1f
      offset = 1

      if argument == 31
        case major
        when 4
          items = []
          remaining = data.byteslice(offset..-1)
          until remaining.bytes.first == 0xff
            item, remaining = decode_value(remaining)
            items << item
          end
          return [items, remaining.byteslice(1..-1)]
        when 5
          map = {}
          remaining = data.byteslice(offset..-1)
          until remaining.bytes.first == 0xff
            key, remaining = decode_value(remaining)
            value, remaining = decode_value(remaining)
            map[key] = value
          end
          return [map, remaining.byteslice(1..-1)]
        end
      end

      if argument >= 24
        size = argument - 23
        argument = data.byteslice(offset, size).unpack1("C") if size == 1
        argument = data.byteslice(offset, size).unpack1("S>") if size == 2
        argument = data.byteslice(offset, size).unpack1("L>") if size == 4
        argument = data.byteslice(offset, size).unpack1("Q>") if size == 8
        offset += size
      end

      case major
      when 0 then [argument, data.byteslice(offset..-1)]
      when 1 then [-1 - argument, data.byteslice(offset..-1)]
      when 2
        bytes = data.byteslice(offset, argument)
        [bytes, data.byteslice(offset + argument..-1)]
      when 3
        text = data.byteslice(offset, argument)
        [text.force_encoding(Encoding::UTF_8), data.byteslice(offset + argument..-1)]
      when 4
        items = []
        remaining = data.byteslice(offset..-1)
        argument.times do
          item, remaining = decode_value(remaining)
          items << item
        end
        [items, remaining]
      when 5
        map = {}
        remaining = data.byteslice(offset..-1)
        argument.times do
          key, remaining = decode_value(remaining)
          value, remaining = decode_value(remaining)
          map[key] = value
        end
        [map, remaining]
      when 6
        value, remaining = decode_value(data.byteslice(offset..-1))
        [CBOR::Tagged.new(argument, value), remaining]
      when 7
        return [false, data.byteslice(offset..-1)] if byte == 0xf4
        return [true, data.byteslice(offset..-1)] if byte == 0xf5
        return [nil, data.byteslice(offset..-1)] if byte == 0xf6

        decoded = ::CBOR.decode(data)
        [decoded, "".b]
      else
        decoded = ::CBOR.decode(data)
        [decoded, "".b]
      end
    end
  end
end
