# frozen_string_literal: true

require "cbor"
require "cose"

RSpec.describe "RFC 9338 Countersignatures v2" do
  let(:message) { "fixed small message".b }
  let(:external_aad) { "archive-aad".b }

  let(:original_key) { build_key("original") }
  let(:counter_key) { build_key("counter-a") }
  let(:other_counter_key) { build_key("counter-b") }
  let(:nested_key) { build_key("nested") }

  let(:sign1) do
    cbor = sign1_cbor(original_key, message, external_aad: external_aad)
    COSE::Sign1.deserialize(cbor)
  end

  let(:sign) do
    cbor = sign_cbor([original_key, other_counter_key], message, external_aad: external_aad)
    COSE::Sign.deserialize(cbor)
  end

  it "adds a Countersignature0V2 without changing the original signature" do
    countersigned = sign1.countersign(
      counter_key,
      protected_headers: {1 => -7},
      external_aad: external_aad
    )

    expect(countersigned.signature).to eq(sign1.signature)
    expect(sign1.unprotected_headers).not_to have_key(20)
    expect(countersigned.message_countersignatures_v2.size).to eq(1)
    expect(countersigned.message_countersignatures_v2.first).to be_sign1
    expect(countersigned.message_countersignatures_v2.first.target).to eq(:message)

    result = verify_all(countersigned, [original_key, counter_key], external_aad: external_aad).first
    expect(result).to be_valid
    expect(result.countersignatures.map(&:status)).to eq([:valid])
  end

  it "reads and verifies CountersignatureV2 against a selected COSE_Sign signature item" do
    countersigned = sign.countersign(
      counter_key,
      target: 1,
      protected_headers: {1 => -7},
      external_aad: external_aad
    )

    target = countersigned.signatures[1]
    expect(target.unprotected_headers[19]).to be_a(Array)
    expect(countersigned.signatures[0].unprotected_headers).not_to have_key(19)
    expect(countersigned.countersignatures_v2(1).size).to eq(1)
    expect(countersigned.countersignatures_v2(0)).to eq([])
    expect(countersigned.countersignatures_v2(1).first).to be_signature
    expect(countersigned.countersignatures_v2(1).first.target).to eq(:signature)

    results = verify_all(countersigned, [original_key, other_counter_key, counter_key], external_aad: external_aad)
    expect(results.map { |result| [result.name, result.status, result.countersignatures.map(&:status)] }).to eq(
      [
        ["signature/0", :valid, []],
        ["signature/1", :valid, [:valid]]
      ]
    )
  end

  it "supports several countersignatures and nested countersignatures" do
    first = sign.countersign(counter_key, target: 0, protected_headers: {1 => -7}, external_aad: external_aad)
    second = first.countersign(other_counter_key, target: 0, protected_headers: {1 => -7}, external_aad: external_aad)
    nested = second.countersign(
      nested_key,
      target: [0, 1],
      protected_headers: {1 => -7},
      external_aad: external_aad
    )

    results = verify_all(
      nested,
      [original_key, other_counter_key, counter_key, nested_key],
      external_aad: external_aad
    )
    root = results.first
    nested_counters = root.countersignatures[1].countersignatures

    expect(root.countersignatures.map(&:status)).to eq(%i[valid valid])
    expect(nested_counters.map(&:status)).to eq([:valid])
  end

  it "verifies deeper nested levels with their chosen targets" do
    first = sign1.countersign(counter_key, protected_headers: {1 => -7}, external_aad: external_aad)
    second = first.countersign(other_counter_key, target: [0], protected_headers: {1 => -7}, external_aad: external_aad)
    third = second.countersign(nested_key, target: [0, 0], protected_headers: {1 => -7}, external_aad: external_aad)

    result = verify_all(
      third,
      [original_key, counter_key, other_counter_key, nested_key],
      external_aad: external_aad
    ).first

    deepest = result.countersignatures.first.countersignatures.first.countersignatures.first
    expect(deepest.name).to eq("countersignature/0/countersignature/0/countersignature/0")
    expect(deepest).to be_valid
  end

  it "binds external_aad for the selected COSE_Sign signature item" do
    first_aad = "aad-0".b
    second_aad = "aad-1".b
    cbor = signers_cbor(
      [original_key, other_counter_key],
      message,
      external_aads: [first_aad, second_aad]
    )
    first_message = COSE::Sign.deserialize(cbor)
    countersigned = first_message.countersign(
      counter_key,
      target: 0,
      protected_headers: {1 => -7},
      external_aad: first_aad
    )
    results = countersigned.verify_all(
      verify_keys([original_key, other_counter_key, counter_key]),
      external_aad: {0 => first_aad, 1 => second_aad}
    )

    expect(results.map(&:status)).to eq(%i[valid valid])
    expect(results.first.countersignatures.map(&:status)).to eq([:valid])
  end

  it "binds external_aad to the countersigned target" do
    countersigned = sign1.countersign(counter_key, protected_headers: {1 => -7}, external_aad: external_aad)
    result = verify_all(countersigned, [original_key, counter_key], external_aad: "different".b).first

    expect(result).to be_invalid
    expect(result.countersignatures.first).to be_invalid
  end

  it "fails when a countersignature is copied to another object with the same payload" do
    countersigned = sign1.countersign(counter_key, protected_headers: {1 => -7}, external_aad: external_aad)
    replacement_signing_key = build_key(original_key.kid)
    replacement = COSE::Sign1.deserialize(
      sign1_cbor(replacement_signing_key, message, external_aad: external_aad)
    )
    transplanted = COSE::Sign1.new(
      payload: replacement.payload,
      signature: replacement.signature,
      protected_headers: replacement.protected_headers,
      serialized_protected_headers: replacement.protected_header_bytes,
      unprotected_headers: replacement.unprotected_headers.merge(
        20 => countersigned.unprotected_headers[20]
      )
    )

    key_map = {original_key.kid => original_key, counter_key.kid => counter_key}
    result = transplanted.verify_all(key_map, external_aad: external_aad).first

    expect(result).to be_invalid
    expect(result.countersignatures.first).to be_invalid
  end

  it "fails when a signature-item countersignature is copied to another COSE_Sign signature" do
    countersigned = sign.countersign(
      counter_key,
      target: 0,
      protected_headers: {1 => -7},
      external_aad: external_aad
    )
    replacement_private = build_key(original_key.kid)
    replacement = COSE::Sign.deserialize(
      sign_cbor([replacement_private, other_counter_key], message, external_aad: external_aad)
    )
    transplanted_signers = replacement.signatures.map.with_index do |signature, index|
      next signature unless index.zero?

      COSE::Signature.new(
        protected_headers: signature.protected_headers,
        serialized_protected_headers: signature.protected_header_bytes,
        unprotected_headers: signature.unprotected_headers.merge(
          19 => countersigned.signatures[0].unprotected_headers[19]
        ),
        signature: signature.signature
      )
    end
    transplanted = COSE::Sign.new(
      payload: replacement.payload,
      signatures: transplanted_signers,
      protected_headers: replacement.protected_headers,
      serialized_protected_headers: replacement.protected_header_bytes,
      unprotected_headers: replacement.unprotected_headers
    )

    result = transplanted.verify_all(
      {
        original_key.kid => original_key,
        other_counter_key.kid => other_counter_key,
        counter_key.kid => counter_key
      },
      external_aad: external_aad
    ).first

    expect(result).to be_invalid
    expect(result.countersignatures.first).to be_invalid
  end

  it "does not interpret legacy countersignature labels as v2" do
    legacy_value = [CBOR.encode(1 => -7), {4 => "legacy"}, "legacy-signature".b]
    message_with_legacy = COSE::Sign1.new(
      payload: sign1.payload,
      signature: sign1.signature,
      protected_headers: sign1.protected_headers,
      serialized_protected_headers: sign1.protected_header_bytes,
      unprotected_headers: sign1.unprotected_headers.merge(11 => legacy_value, 12 => legacy_value)
    )

    expect(message_with_legacy.message_countersignatures_v2).to eq([])
    expect(message_with_legacy.unprotected_headers.keys).to include(11, 12)
  end

  it "reports missing verification keys separately from valid and invalid signatures" do
    countersigned = sign1.countersign(counter_key, protected_headers: {1 => -7}, external_aad: external_aad)
    result = verify_all(countersigned, [], external_aad: external_aad).first

    expect(result).to be_missing_key
    expect(result).not_to be_valid
    expect(result).not_to be_invalid
    expect(result.countersignatures.first).to be_missing_key
  end

  it "uses original protected header bytes rather than a re-encoded map" do
    raw_protected = "\xA2\x01&\x0F\x00".b
    input = CBOR.encode(["Signature1", raw_protected, external_aad, message])
    cbor = CBOR::Tagged.new(
      18,
      [raw_protected, {4 => original_key.kid}, message, sign_data(original_key, input)]
    ).to_cbor
    decoded = COSE::Sign1.deserialize(cbor)
    countersigned = decoded.countersign(counter_key, protected_headers: {1 => -7}, external_aad: external_aad)
    result = verify_all(countersigned, [original_key, counter_key], external_aad: external_aad).first

    expect(result).to be_valid
    expect(result.countersignatures.first).to be_valid
  end

  def build_key(kid)
    pkey = OpenSSL::PKey::EC.generate("prime256v1")
    COSE::Key::EC2.from_pkey(pkey).tap { |key| key.kid = kid }
  end

  def sign_data(key, data)
    key.to_pkey.sign("SHA256", data)
  end

  def sign1_cbor(key, payload, external_aad: nil)
    protected = CBOR.encode(1 => -7)
    input = CBOR.encode(["Signature1", protected, external_aad || "".b, payload])
    CBOR::Tagged.new(18, [protected, {4 => key.kid}, payload, sign_data(key, input)]).to_cbor
  end

  def sign_cbor(keys, payload, external_aad: nil)
    signers_cbor(keys, payload, external_aads: [external_aad] * keys.size)
  end

  def signers_cbor(keys, payload, external_aads:)
    body_protected = "".b
    signers = keys.map do |key|
      signer_protected = CBOR.encode(1 => -7)
      aad = external_aads[keys.index(key)]
      input = CBOR.encode(["Signature", body_protected, signer_protected, aad || "".b, payload])
      [signer_protected, {4 => key.kid}, sign_data(key, input)]
    end
    CBOR::Tagged.new(98, [body_protected, {}, payload, signers]).to_cbor
  end

  def verify_all(message, keys, external_aad:)
    message.verify_all(verify_keys(keys), external_aad: external_aad)
  end

  def verify_keys(keys)
    keys.each_with_object({}) { |key, map| map[key.kid] = key }
  end
end
