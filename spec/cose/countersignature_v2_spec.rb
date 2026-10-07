# frozen_string_literal: true

require "cbor"
require "cose/cbor_safe"
require "cose/countersignature_v2"
require "cose/key"
require "cose/sign"
require "cose/sign1"
require "openssl"

RSpec.describe "RFC 9338 CountersignatureV2" do
  if curve_25519_supported?
    def ed25519_key(kid)
      pkey = OpenSSL::PKey.generate_key("ED25519")
      key = COSE::Key.from_pkey(pkey)
      key.alg = -8
      key.kid = kid
      [pkey, key]
    end

    def sign1_message(pkey, key, payload: "small message".b, external_aad: "".b, protected_headers: nil)
      protected_headers ||= "\xbf\x01\x27\xff".b
      tbs = CBOR.encode(["Signature1", protected_headers, external_aad, payload])
      signature = pkey.sign(nil, tbs)
      CBOR.encode([protected_headers, { 4 => key.kid }, payload, signature])
    end

    def sign_message(pkey, key, payload: "small message".b, external_aad: "".b)
      protected_headers = "\xbf\x01\x27\xff".b
      tbs = CBOR.encode(["Signature", "".b, protected_headers, external_aad, payload])
      signature = pkey.sign(nil, tbs)
      CBOR.encode(["".b, {}, payload, [[protected_headers, { 4 => key.kid }, signature]]])
    end

    def replace_header(cbor, label, value)
      array = COSE::CborSafe.decode(cbor)
      array[1] = array[1].merge(label => value)
      CBOR.encode(array)
    end

    let(:payload) { "small message".b }

    it "adds Countersignature0V2 without changing the original signature" do
      signer_pkey, signer_key = ed25519_key("signer")
      _archive_pkey, archive_key = ed25519_key("archive")
      original_cbor = sign1_message(signer_pkey, signer_key)
      original_signature = COSE::Sign1.deserialize(original_cbor).signature

      countersigned_cbor = COSE::Sign1.deserialize(original_cbor).add_countersignature_v2(archive_key)
      countersigned = COSE::Sign1.deserialize(countersigned_cbor)

      expect(countersigned.signature).to eq(original_signature)
      expect(countersigned.unprotected_headers.keys).to eq([4, 20])
      expect(countersigned.countersignatures_v2.map(&:label)).to eq([20])
      expect(countersigned.headers.kid).to eq(signer_key.kid)
      expect(countersigned.verify(signer_key)).to be_truthy
    end

    it "keeps the original protected header bytes in the countersigned target" do
      signer_pkey, signer_key = ed25519_key("signer")
      _archive_pkey, archive_key = ed25519_key("archive")
      original_cbor = sign1_message(signer_pkey, signer_key)
      countersigned_cbor = COSE::Sign1.deserialize(original_cbor).add_countersignature_v2(archive_key)
      countersigned = COSE::Sign1.deserialize(countersigned_cbor)
      counter = countersigned.countersignatures_v2.first

      expect(COSE::CborSafe.decode(counter.message.payload).first).to eq("\xbf\x01\x27\xff".b)
      target = COSE::CborSafe.decode(counter.message.payload)
      expect(target[1]).to eq(4 => signer_key.kid)
      expect(target[2]).to eq(payload)
      expect(target[3]).to eq(countersigned.signature)
      result = countersigned.verify_with_countersignatures_v2(
        "signer" => signer_key,
        "archive" => archive_key
      )
      expect(result[:countersignatures].first.valid?).to eq(true)
    end

    it "supports multiple CountersignatureV2 values and cumulative nesting" do
      signer_pkey, signer_key = ed25519_key("signer")
      _first_pkey, first_key = ed25519_key("first")
      _second_pkey, second_key = ed25519_key("second")
      message = COSE::Sign1.deserialize(sign1_message(signer_pkey, signer_key))

      first_cbor = message.add_countersignature_v2(first_key, multiple: true)
      second_cbor = COSE::Sign1.deserialize(first_cbor).add_countersignature_v2(second_key, multiple: true)
      countersigned = COSE::Sign1.deserialize(second_cbor)
      results = countersigned.verify_with_countersignatures_v2(
        "signer" => signer_key,
        "first" => first_key,
        "second" => second_key
      )

      expect(countersigned.unprotected_headers.keys).to eq([4, 19])
      expect(results[:countersignatures].map(&:kid)).to eq(%w[first second])
      expect(results[:countersignatures].map(&:signature_index)).to eq([0, 1])
      expect(results[:countersignatures]).to all(be_valid)
      expect(COSE::Sign1.deserialize(first_cbor).countersignatures_v2.first.countersigner_signatures.size).to eq(1)
      expect(countersigned.countersignatures_v2.first.countersigner_signatures.size).to eq(2)
    end

    it "binds the countersigner external_aad" do
      signer_pkey, signer_key = ed25519_key("signer")
      _archive_pkey, archive_key = ed25519_key("archive")
      countersigned_cbor = COSE::Sign1.deserialize(
        sign1_message(signer_pkey, signer_key)
      ).add_countersignature_v2(archive_key, external_aad: "counter aad".b)
      countersigned = COSE::Sign1.deserialize(countersigned_cbor)
      keys = { "signer" => signer_key, "archive" => archive_key }

      expect(countersigned.verify_with_countersignatures_v2(
        keys,
        counter_external_aads: { message: "counter aad".b }
      )[:countersignatures].first).to be_valid
      expect(countersigned.verify_with_countersignatures_v2(
        keys,
        counter_external_aads: { message: "different aad".b }
      )[:countersignatures].first.result).to be_invalid
    end

    it "binds original external_aad separately from countersigner external_aad" do
      signer_pkey, signer_key = ed25519_key("signer")
      _archive_pkey, archive_key = ed25519_key("archive")
      original_cbor = sign1_message(
        signer_pkey,
        signer_key,
        external_aad: "original aad".b
      )
      countersigned_cbor = COSE::Sign1.deserialize(original_cbor).add_countersignature_v2(
        archive_key,
        external_aad: "counter aad".b
      )
      countersigned = COSE::Sign1.deserialize(countersigned_cbor)
      results = countersigned.verify_with_countersignatures_v2(
        {
          "signer" => signer_key,
          "archive" => archive_key
        },
        external_aad: "original aad".b,
        counter_external_aads: { message: "counter aad".b }
      )

      expect(results[:original]).to be_valid
      expect(results[:countersignatures]).to all(be_valid)
    end

    it "reports missing keys separately from signature failure and success" do
      signer_pkey, signer_key = ed25519_key("signer")
      _archive_pkey, archive_key = ed25519_key("archive")
      countersigned = COSE::Sign1.deserialize(
        COSE::Sign1.deserialize(sign1_message(signer_pkey, signer_key)).add_countersignature_v2(archive_key)
      )

      results = countersigned.verify_with_countersignatures_v2("signer" => signer_key)

      expect(results[:original]).to be_valid
      expect(results[:countersignatures].first).to be_missing_key
      expect(results[:countersignatures].first).not_to be_valid
      expect(results[:countersignatures].first.result.error).to be_a(COSE::MissingVerificationKeyError)
    end

    it "rejects a countersignature copied to another Sign1 with the same payload" do
      signer_pkey, signer_key = ed25519_key("signer")
      other_pkey, other_key = ed25519_key("signer")
      _archive_pkey, archive_key = ed25519_key("archive")
      original = COSE::Sign1.deserialize(sign1_message(signer_pkey, signer_key))
      countersigned_cbor = original.add_countersignature_v2(archive_key)
      countersigned = COSE::CborSafe.decode(countersigned_cbor)
      copied_header = countersigned[1][20]
      replacement_cbor = sign1_message(other_pkey, other_key)
      copied_cbor = replace_header(replacement_cbor, 20, copied_header)
      copied = COSE::Sign1.deserialize(copied_cbor)

      result = copied.verify_with_countersignatures_v2(
        "signer" => other_key,
        "archive" => archive_key
      )[:countersignatures].first

      expect(copied.payload).to eq(original.payload)
      expect(copied.signature).not_to eq(original.signature)
      expect(result).to be_invalid
      expect(result).not_to be_missing_key
    end

    it "does not interpret legacy countersignature labels as V2" do
      signer_pkey, signer_key = ed25519_key("signer")
      original_cbor = sign1_message(signer_pkey, signer_key)
      legacy_value = "legacy countersignature".b
      legacy_cbor = replace_header(original_cbor, 11, legacy_value)
      message = COSE::Sign1.deserialize(legacy_cbor)

      expect(message.countersignatures_v2).to eq([])
      expect { message.add_countersignature_v2(signer_key) }.to raise_error(
        COSE::Error,
        /Legacy countersignature label 11/
      )
    end

    it "supports whole-message and signature-item countersignatures on COSE_Sign" do
      signer_pkey, signer_key = ed25519_key("signer")
      _archive_pkey, archive_key = ed25519_key("archive")
      _item_pkey, item_key = ed25519_key("item")
      message = COSE::Sign.deserialize(sign_message(signer_pkey, signer_key))

      message_cbor = message.add_countersignature_v2(archive_key)
      complete_cbor = COSE::Sign.deserialize(message_cbor).add_countersignature_v2(item_key, target: 0)
      complete = COSE::Sign.deserialize(complete_cbor)
      results = complete.verify_with_countersignatures_v2(
        "signer" => signer_key,
        "archive" => archive_key,
        "item" => item_key
      )

      expect(complete.unprotected_headers.keys).to eq([19])
      expect(complete.signatures.first.unprotected_headers.keys).to eq([4, 20])
      expect(results[:original_signatures].first[:result]).to be_valid
      expect(results[:countersignatures].map(&:target)).to eq(%i[message signature])
      expect(results[:countersignatures].map(&:kid)).to eq(%w[archive item])
      expect(results[:countersignatures]).to all(be_valid)
    end

    it "replaces a signature-item Countersignature0V2 when another single V2 counter is added" do
      signer_pkey, signer_key = ed25519_key("signer")
      _first_pkey, first_key = ed25519_key("first")
      _second_pkey, second_key = ed25519_key("second")
      message = COSE::Sign.deserialize(sign_message(signer_pkey, signer_key))
      first_cbor = message.add_countersignature_v2(first_key, target: 0)
      complete_cbor = COSE::Sign.deserialize(first_cbor).add_countersignature_v2(second_key, target: 0)
      complete = COSE::Sign.deserialize(complete_cbor)
      results = complete.verify_with_countersignatures_v2(
        "signer" => signer_key,
        "first" => first_key,
        "second" => second_key
      )

      expect(complete.signatures.first.unprotected_headers.keys).to eq([4, 20])
      expect(results[:countersignatures].map(&:kid)).to eq(%w[second])
      expect(results[:countersignatures]).to all(be_valid)
    end

    it "rejects a Sign signature-item countersignature moved to another original signature" do
      signer_pkey, signer_key = ed25519_key("signer")
      other_pkey, other_key = ed25519_key("signer")
      _item_pkey, item_key = ed25519_key("item")
      signed = COSE::Sign.deserialize(sign_message(signer_pkey, signer_key))
      complete = COSE::CborSafe.decode(signed.add_countersignature_v2(item_key, target: 0))
      replacement = COSE::CborSafe.decode(sign_message(other_pkey, other_key))
      replacement[3][0][1] = replacement[3][0][1].merge(20 => complete[3][0][1][20])
      copied = COSE::Sign.deserialize(CBOR.encode(replacement))

      result = copied.verify_with_countersignatures_v2(
        "signer" => other_key,
        "item" => item_key
      )[:countersignatures].first

      expect(copied.payload).to eq(signed.payload)
      expect(copied.signatures.first.signature).not_to eq(signed.signatures.first.signature)
      expect(result.target).to eq(:signature)
      expect(result).to be_invalid
    end
  end
end
