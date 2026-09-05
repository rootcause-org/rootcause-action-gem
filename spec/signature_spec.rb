# frozen_string_literal: true

RSpec.describe RootCause::Embassy::Signature do
  let(:secret) { "s3cr3t" }
  let(:body) { %({"a":1}) }

  it "round-trips: a freshly signed payload verifies" do
    sig = described_class.sign(body, secret: secret)
    expect(sig).to start_with("sha256=")
    expect(described_class.valid?(sig, body, secret: secret)).to be(true)
  end

  it "rejects a forgery, the wrong secret, and a tampered body" do
    expect(described_class.valid?("sha256=deadbeef", body, secret: secret)).to be(false)
    expect(described_class.valid?(described_class.sign(body, secret: "other"), body, secret: secret)).to be(false)
    expect(described_class.valid?(described_class.sign(body, secret: secret), %({"a":2}), secret: secret)).to be(false)
  end

  it "treats a missing/nil signature as invalid (never raises)" do
    expect(described_class.valid?(nil, body, secret: secret)).to be(false)
    expect(described_class.valid?("", body, secret: secret)).to be(false)
  end

  # CONTRACT.md, "Three keys": a blank key is trivially forgeable, so it fails
  # closed in BOTH directions — never sign with one, never accept one.
  it "fails closed on a blank secret when signing and when verifying" do
    ["", "   ", nil].each do |blank|
      expect { described_class.sign(body, secret: blank) }.to raise_error(ArgumentError, /secret is required/)
      expect(described_class.valid?("sha256=whatever", body, secret: blank)).to be(false)
    end
  end
end
