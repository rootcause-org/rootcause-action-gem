# frozen_string_literal: true

SchemaError = RootCause::Embassy::SchemaError

RSpec.describe RootCause::Embassy::Schema do
  def validate(params, schema)
    described_class.validate!(params, schema)
  end

  # The whole type vocabulary as one table: what each type accepts, and the
  # near-misses it must refuse (a float for integer, a boolean for a number, a
  # mixed array). Coercion is never an option — a type mismatch is a refusal.
  it "accepts each supported type and refuses its near-misses" do
    [
      ["string", "hi"],
      ["integer", 3],
      ["number", 3],
      ["number", 3.5],
      ["boolean", false],
      ["string[]", %w[a b]]
    ].each do |type, value|
      expect(validate({"x" => value}, {"x" => {"type" => type}})).to eq({x: value}), "#{type}: #{value.inspect}"
    end

    [
      ["integer", 3.5],
      ["boolean", "true"],
      ["integer", true],
      ["number", true],
      ["string[]", ["a", 1]]
    ].each do |type, value|
      expect { validate({"x" => value}, {"x" => {"type" => type}}) }
        .to raise_error(SchemaError), "#{type}: #{value.inspect}"
    end
  end

  it "rejects a missing required param" do
    expect { validate({}, {"email" => {"type" => "string"}}) }.to raise_error(SchemaError, /missing required/)
  end

  it "allows a missing optional param and omits it" do
    out = validate({}, {"email" => {"type" => "string", "required" => false}})
    expect(out).to eq({})
  end

  it "rejects an unknown param (fail closed)" do
    expect { validate({"evil" => 1}, {"x" => {"type" => "integer"}}) }.to raise_error(SchemaError, /unknown/)
  end

  it "reserves tenant and principal selectors for signed host context" do
    %w[
      tenant_id tenant_slug tenant_scope_value RC_TENANT_ID RC_TENANT_SLUG RC_TENANT_SCOPE_VALUE
      RC_TENANT_ANY principal_kind principal_external_id principal_claim_user_id
      RC_PRINCIPAL_KIND RC_PRINCIPAL_CLAIM_USER_ID
    ].each do |name|
      expect { validate({name => "attacker"}, {name => {"type" => "string"}}) }
        .to raise_error(SchemaError, /host-owned/)
      expect { validate({}, {name => {"type" => "string", "required" => false}}) }
        .to raise_error(SchemaError, /host-owned/)
    end
  end

  it "rejects an unsupported type in the schema" do
    expect { validate({"x" => 1}, {"x" => {"type" => "bigint"}}) }.to raise_error(SchemaError, /unsupported type/)
  end

  it "rejects a bare-string spec (shorthand form) as a SchemaError, not a crash" do
    # A malformed schema like {"email" => "string"} must fail closed with a
    # typed SchemaError — never escape as a NoMethodError.
    expect { validate({"email" => "x@y.z"}, {"email" => "string"}) }
      .to raise_error(SchemaError, /must be an object/)
  end

  it "returns a frozen, symbol-keyed hash with frozen values" do
    out = validate({"name" => "ann", "tags" => ["a"]}, {"name" => {"type" => "string"}, "tags" => {"type" => "string[]"}})
    expect(out).to be_frozen
    expect(out[:name]).to be_frozen
    expect(out[:tags]).to be_frozen
    expect(out[:tags].first).to be_frozen
  end

  describe "JSON-Schema object form" do
    let(:schema) do
      {"type" => "object", "properties" => {"email" => {"type" => "string"}}, "required" => ["email"]}
    end

    it "validates required from the required array" do
      expect(validate({"email" => "x@y.z"}, schema)).to eq({email: "x@y.z"})
      expect { validate({}, schema) }.to raise_error(SchemaError, /missing required/)
    end
  end

  it "rejects a missing or non-hash schema" do
    expect { validate({}, nil) }.to raise_error(SchemaError)
    expect { validate({}, "nope") }.to raise_error(SchemaError)
  end
end
