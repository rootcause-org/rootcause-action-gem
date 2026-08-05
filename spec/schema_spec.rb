# frozen_string_literal: true

SchemaError = RootCause::Embassy::SchemaError

RSpec.describe RootCause::Embassy::Schema do
  def validate(params, schema)
    described_class.validate!(params, schema)
  end

  describe "each supported type" do
    it "accepts string" do
      out = validate({"x" => "hi"}, {"x" => {"type" => "string"}})
      expect(out).to eq({x: "hi"})
    end

    it "accepts integer but rejects a float for it" do
      expect(validate({"x" => 3}, {"x" => {"type" => "integer"}})).to eq({x: 3})
      expect { validate({"x" => 3.5}, {"x" => {"type" => "integer"}}) }.to raise_error(SchemaError)
    end

    it "accepts number for both integer and float" do
      expect(validate({"x" => 3}, {"x" => {"type" => "number"}})).to eq({x: 3})
      expect(validate({"x" => 3.5}, {"x" => {"type" => "number"}})).to eq({x: 3.5})
    end

    it "accepts boolean true/false but not a string" do
      expect(validate({"x" => false}, {"x" => {"type" => "boolean"}})).to eq({x: false})
      expect { validate({"x" => "true"}, {"x" => {"type" => "boolean"}}) }.to raise_error(SchemaError)
    end

    it "does not accept a boolean as integer or number" do
      expect { validate({"x" => true}, {"x" => {"type" => "integer"}}) }.to raise_error(SchemaError)
      expect { validate({"x" => true}, {"x" => {"type" => "number"}}) }.to raise_error(SchemaError)
    end

    it "accepts string[] of strings, rejects a mixed array" do
      expect(validate({"x" => %w[a b]}, {"x" => {"type" => "string[]"}})).to eq({x: %w[a b]})
      expect { validate({"x" => ["a", 1]}, {"x" => {"type" => "string[]"}}) }.to raise_error(SchemaError)
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

  it "reserves tenant selectors for signed host context" do
    %w[tenant_id tenant_slug tenant_scope_value RC_TENANT_ID RC_TENANT_SLUG RC_TENANT_SCOPE_VALUE].each do |name|
      expect { validate({name => "attacker"}, {name => {"type" => "string"}}) }
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
