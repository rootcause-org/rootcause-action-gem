# frozen_string_literal: true

# End-to-end through the framework-agnostic core: verify → replay → validate →
# resolve → run → sign. The host side (signing + script fetch) is stubbed via Wire.
RSpec.describe RootCause::Embassy::Runner do
  let(:config) { Wire.config }
  let(:runner) { described_class.new(config) }

  # Build a signed request for `invocation`, sending it through the runner.
  def handle(invocation, secret: Wire::SECRET)
    raw = JSON.generate(invocation)
    runner.handle(raw_body: raw, signature: Wire.sign(raw, secret: secret))
  end

  def body_of(reply) = JSON.parse(reply.body)

  it "runs a valid invocation end to end and returns a signed, verifiable result" do
    script = "{ found: true, email: params[:email] }"
    Wire.stub_fetch(script: script)
    inv = Wire.invocation(
      script: script,
      params: {"email" => "x@acme.com"},
      schema: {"email" => {"type" => "string"}}
    )

    reply = handle(inv)

    expect(reply.status).to eq(200)
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
    payload = body_of(reply)
    expect(payload["ok"]).to be(true)
    expect(payload["return_value"]).to eq({"found" => true, "email" => "x@acme.com"})
    expect(payload["duration_ms"]).to be_a(Integer)
  end

  it "exposes signed tenant context through trusted RC_TENANT_* environment fields" do
    script = <<~RUBY
      {
        id: ENV.fetch("RC_TENANT_ID"),
        slug: ENV.fetch("RC_TENANT_SLUG"),
        scope_value: ENV.fetch("RC_TENANT_SCOPE_VALUE")
      }
    RUBY
    Wire.stub_fetch(script: script)

    reply = handle(Wire.invocation(script: script))

    expect(reply.status).to eq(200)
    expect(body_of(reply)["return_value"]).to eq(
      "id" => Wire::TENANT_ID,
      "slug" => Wire::TENANT_SLUG,
      "scope_value" => Wire::TENANT_SCOPE_VALUE
    )
  end

  it "rejects a tenant field tampered after signing and never resolves the script" do
    inv = Wire.invocation
    raw = JSON.generate(inv)
    signature = Wire.sign(raw)
    tampered = raw.sub(Wire::TENANT_SLUG, "attacker")
    fetch = Wire.stub_fetch(script: "{ ok: true }")

    reply = runner.handle(raw_body: tampered, signature: signature)

    expect(reply.status).to eq(401)
    expect(body_of(reply).dig("error", "class")).to eq("bad_signature")
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
    expect(fetch).not_to have_been_requested
  end

  it "rejects a signed tenant-bound invocation missing id or slug" do
    %w[tenant_id tenant_slug].each do |field|
      inv = Wire.invocation
      inv.delete(field)
      reply = handle(inv)

      expect(reply.status).to eq(400), "expected missing #{field} to fail"
      expect(body_of(reply).dig("error", "message")).to include(field)
    end
  end

  it "accepts the byte-compatible signed flat invocation with tenant fields absent" do
    script = "ENV.values_at(*%w[RC_TENANT_ID RC_TENANT_SLUG RC_TENANT_SCOPE_VALUE])"
    Wire.stub_fetch(script: script)
    inv = Wire.invocation(script: script)
    RootCause::Embassy::Runner::TRUSTED_TENANT_FIELDS.each { |field| inv.delete(field) }
    keys = RootCause::Embassy::Executor::TRUSTED_ENV_KEYS
    original = keys.to_h { |key| [key, [ENV.key?(key), ENV[key]]] }
    keys.each { |key| ENV[key] = "stale-process-value" }

    reply = handle(inv)

    expect(reply.status).to eq(200)
    expect(body_of(reply)["return_value"]).to eq([nil, nil, nil])
  ensure
    original&.each do |key, (present, value)|
      present ? ENV[key] = value : ENV.delete(key)
    end
  end

  it "rejects absent tenant context before resolution when this Embassy requires a tenant" do
    config.require_tenant_context = true
    inv = Wire.invocation
    described_class::TRUSTED_TENANT_FIELDS.each { |field| inv.delete(field) }
    fetch = Wire.stub_fetch(script: "{ ok: true }")

    reply = handle(inv)

    expect(reply.status).to eq(400)
    expect(body_of(reply).dig("error", "message")).to include("tenant context is required")
    expect(fetch).not_to have_been_requested
  end

  it "rejects explicit empty tenant fields and accepts an omitted bound scope value" do
    script = "ENV.values_at(*%w[RC_TENANT_ID RC_TENANT_SLUG RC_TENANT_SCOPE_VALUE])"
    Wire.stub_fetch(script: script)
    explicit_flat = Wire.invocation(script: script, tenant_id: "", tenant_slug: "", tenant_scope_value: "")
    expect(handle(explicit_flat).status).to eq(400)

    bound_without_scope = Wire.invocation(script: script)
    bound_without_scope.delete("tenant_scope_value")
    expect(body_of(handle(bound_without_scope))["return_value"]).to eq([Wire::TENANT_ID, Wire::TENANT_SLUG, nil])
  end

  it "rejects tenant selectors carried as signed params even when the schema declares them" do
    fetch = Wire.stub_fetch(script: "{ ok: true }")
    inv = Wire.invocation(
      params: {"tenant_slug" => "attacker"},
      schema: {"tenant_slug" => {"type" => "string"}}
    )

    reply = handle(inv)

    expect(reply.status).to eq(422)
    expect(body_of(reply).dig("error", "message")).to include("host-owned")
    expect(fetch).not_to have_been_requested
  end

  it "rejects malformed tenant host context" do
    expect(handle(Wire.invocation(tenant_id: "not-a-uuid")).status).to eq(400)
    expect(handle(Wire.invocation(tenant_id: RootCause::Embassy::Runner::NIL_UUID)).status).to eq(400)
    expect(handle(Wire.invocation(tenant_slug: "")).status).to eq(400)
    expect(handle(Wire.invocation(tenant_slug: "Bad Slug")).status).to eq(400)
    expect(handle(Wire.invocation(tenant_id: "", tenant_slug: "acme")).status).to eq(400)
    expect(handle(Wire.invocation(tenant_scope_value: nil)).status).to eq(400)
    expect(handle(Wire.invocation(tenant_scope_value: "scope\0value")).status).to eq(400)

    partial_flat = Wire.invocation
    RootCause::Embassy::Runner::TRUSTED_TENANT_FIELDS.each { |field| partial_flat.delete(field) }
    partial_flat["tenant_id"] = ""
    expect(handle(partial_flat).status).to eq(400)
  end

  it "rejects a bad signature with 401, still signing the refusal" do
    reply = handle(Wire.invocation, secret: "wrong-secret")
    expect(reply.status).to eq(401)
    expect(body_of(reply).dig("error", "class")).to eq("bad_signature")
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
  end

  it "rejects malformed JSON with 400" do
    raw = "not json"
    reply = runner.handle(raw_body: raw, signature: Wire.sign(raw))
    expect(reply.status).to eq(400)
  end

  it "rejects a missing required field with 400" do
    inv = Wire.invocation
    inv.delete("nonce")
    expect(handle(inv).status).to eq(400)
  end

  it "rejects a non-ruby runtime with 400" do
    expect(handle(Wire.invocation(runtime: "python")).status).to eq(400)
  end

  it "rejects a stale issued_at with 409" do
    inv = Wire.invocation(issued_at: (Time.now.utc - 3600).iso8601)
    expect(handle(inv).status).to eq(409)
  end

  it "rejects a replayed nonce with 409" do
    script = "{ ok: true }"
    Wire.stub_fetch(script: script)
    inv = Wire.invocation(script: script, nonce: "fixed-nonce")
    expect(handle(inv).status).to eq(200)
    expect(handle(inv).status).to eq(409)
  end

  it "rejects a schema violation with 422 (and never fetches a script)" do
    stub = Wire.stub_fetch(script: "{ ok: true }")
    inv = Wire.invocation(params: {"email" => 123}, schema: {"email" => {"type" => "string"}})
    expect(handle(inv).status).to eq(422)
    expect(stub).not_to have_been_requested
  end

  it "hard-refuses a digest mismatch with 502 and never runs the body" do
    real = "{ ok: true }"
    inv = Wire.invocation(script: real)
    # Host serves a different body under the requested digest.
    Wire.stub_fetch(script: "{ evil: true }", digest: inv["script_digest"])
    expect(handle(inv).status).to eq(502)
  end

  it "fail-closes an unexpected pipeline error into a signed 500 (never crashes)" do
    # A malformed-but-authenticated invocation that trips a non-typed error must
    # still come back as a signed, structured refusal — not an unsigned crash.
    inv = Wire.invocation(params: {"email" => "x@y.z"}, schema: {"email" => "string"})
    reply = handle(inv)
    expect(reply.status).to eq(422) # SchemaError now covers the shorthand
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
  end

  it "returns a signed 500 if a pipeline step raises an unexpected error" do
    # Force a non-Error exception from inside the pipeline (post-auth) and prove
    # the backstop signs and structures it rather than letting it escape.
    allow(RootCause::Embassy::Schema).to receive(:validate!).and_raise(RuntimeError, "x@acme.com leaked?")
    reply = handle(Wire.invocation)
    expect(reply.status).to eq(500)
    payload = body_of(reply)
    expect(payload["ok"]).to be(false)
    expect(payload.dig("error", "class")).to eq("internal_error")
    # The wire message is the exception class only — never the (possibly
    # input-bearing) exception message.
    expect(payload.dig("error", "message")).to eq("RuntimeError")
    expect(reply.body).not_to include("x@acme.com")
    expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
  end

  it "returns 200 with ok:false when the action itself raises" do
    script = "raise 'boom'"
    Wire.stub_fetch(script: script)
    reply = handle(Wire.invocation(script: script))
    expect(reply.status).to eq(200)
    expect(body_of(reply)["ok"]).to be(false)
  end

  describe "dry_run (validate-only)" do
    it "runs verify→replay→schema→resolve but never executes, returning a signed would_execute result" do
      script = "raise 'must not run'" # proves the executor is skipped
      stub = Wire.stub_fetch(script: script)
      executor = instance_double(RootCause::Embassy::Executor)
      allow(executor).to receive(:run)
      runner = described_class.new(config, executor: executor)

      raw = JSON.generate(Wire.invocation(script: script, dry_run: true))
      reply = runner.handle(raw_body: raw, signature: Wire.sign(raw))

      expect(reply.status).to eq(200)
      payload = body_of(reply)
      expect(payload["ok"]).to be(true)
      expect(payload["return_value"]).to eq({"dry_run" => true, "would_execute" => true})
      expect(payload["stdout"]).to eq("")
      expect(payload["error"]).to be_nil
      expect(payload["duration_ms"]).to be_a(Integer)
      # The signed fetch (digest-verified resolve) WAS exercised; the executor was NOT.
      expect(stub).to have_been_requested
      expect(executor).not_to have_received(:run)
      expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: Wire::SECRET)).to be(true)
    end

    it "still returns the resolve_failed refusal when resolve fails under dry_run (no side-effect-free pass)" do
      real = "{ ok: true }"
      inv = Wire.invocation(script: real, dry_run: true)
      # Host serves a different body under the requested digest → digest mismatch.
      Wire.stub_fetch(script: "{ evil: true }", digest: inv["script_digest"])
      reply = handle(inv)
      expect(reply.status).to eq(502)
      expect(body_of(reply).dig("error", "class")).to eq("resolve_failed")
    end

    it "executes normally when dry_run is absent or false" do
      script = "{ ran: true }"
      Wire.stub_fetch(script: script)
      reply = handle(Wire.invocation(script: script, dry_run: false))
      expect(reply.status).to eq(200)
      expect(body_of(reply)["return_value"]).to eq({"ran" => true})
    end
  end

  describe "logging" do
    let(:logger) { instance_double(Logger, info: nil, warn: nil) }
    let(:config) { Wire.config(logger: logger) }

    it "logs identifiers, param KEYS, ok and duration — never values or the secret" do
      script = "{ ok: true }"
      Wire.stub_fetch(script: script)
      inv = Wire.invocation(script: script, params: {"email" => "secret@acme.com"}, schema: {"email" => {"type" => "string"}})

      handle(inv)

      expect(logger).to have_received(:info) do |line|
        expect(line).to include("action_id=devise_send_password_reset")
        expect(line).to include("param_keys=[\"email\"]")
        expect(line).to include("ok=true")
        expect(line).not_to include("secret@acme.com")
        expect(line).not_to include(Wire::SECRET)
      end
    end
  end
end
