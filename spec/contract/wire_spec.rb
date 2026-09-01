# frozen_string_literal: true

require "digest"

RSpec.describe "hub contract conformance" do
  fixture_dir = File.expand_path("../fixtures/contract", __dir__)
  vectors = JSON.parse(File.read(File.join(fixture_dir, "signing_vectors.json")))

  define_method(:fixture_dir) { fixture_dir }
  define_method(:vectors) { vectors }
  def fixture(path) = File.binread(File.join(fixture_dir, path))
  def reverse_secret = vectors.fetch("secrets").fetch("action_reverse_secret")

  it "records and prints the vendored hub revision" do
    hub_sha = File.read(File.join(fixture_dir, "HUB_SHA")).strip
    warn "rootcause-embassy hub fixtures: #{hub_sha}"
    expect(hub_sha).to match(/\A[0-9a-f]{40}\z/)
  end

  it "replays every body signing vector over its exact bytes" do
    vectors.fetch("bodies").each do |vector|
      bytes = fixture(vector.fetch("file"))
      expect(bytes.bytesize).to eq(vector.fetch("body_bytes")), vector.fetch("name")
      expect(Digest::SHA256.hexdigest(bytes)).to eq(vector.fetch("body_sha256")), vector.fetch("name")
      expect(RootCause::Embassy::Signature.sign(bytes, secret: vector.fetch("secret"))).to eq(vector.fetch("signature")), vector.fetch("name")
      expect(RootCause::Embassy::Signature.valid?(vector.fetch("signature"), bytes, secret: vector.fetch("secret"))).to be(true), vector.fetch("name")
    end
  end

  it "replays raw query signing vectors without re-serializing them" do
    vectors.fetch("query_strings").each do |vector|
      query = fixture(vector.fetch("file"))
      expect(query).to eq(vector.fetch("raw_query")), vector.fetch("name")
      expect(RootCause::Embassy::Signature.sign(query, secret: vector.fetch("secret"))).to eq(vector.fetch("signature")), vector.fetch("name")
    end
  end

  it "decodes action and analysis envelopes with their complete mapped surface" do
    flat = JSON.parse(fixture("actions/invocation_flat.json"))
    tenant = JSON.parse(fixture("actions/invocation_tenant.json"))
    principal = JSON.parse(fixture("actions/invocation_principal.json")).fetch("principal")
    callback = JSON.parse(fixture("analysis/result_callback.json"))
    result = RootCause::Embassy::Result.from_payload(callback)

    expect(flat.fetch("project_id")).to match(/\A[0-9a-f-]{36}\z/)
    expect(flat).not_to have_key("dry_run")
    expect(tenant.slice("tenant_id", "tenant_slug")).to include("tenant_id" => "22222222-2222-2222-2222-222222222222", "tenant_slug" => "acme")
    expect(principal).to eq(
      "kind" => "acme_user",
      "external_id" => "user-8f3",
      "claims" => {"user_id" => "user-8f3", "person_id" => 103, "backup_ids" => %w[backup-7 backup-9]}
    )
    expect(result.note).to include("run trace")
    expect(result.actions.first[:slug]).not_to be_empty
    expect(result.executed_actions.first[:slug]).not_to be_empty
    expect(result.questions.first[:id]).not_to be_empty
    expect(result.delete_ids).not_to be_empty
    expect(result.project_id).to eq(flat.fetch("project_id"))
  end

  it "matches refusal classes to their status vocabulary and keeps their vectors signed" do
    {
      "bad_signature" => 401,
      "replay" => 409,
      "schema_violation" => 422,
      "resolve_failed" => 502
    }.each do |code, status|
      body = fixture("actions/result_refusal_#{code}.json")
      expect(JSON.parse(body).dig("error", "class")).to eq(code)
      expect(status).to be_between(400, 599)
      vector = vectors.fetch("bodies").find { |entry| entry.fetch("file") == "actions/result_refusal_#{code}.json" }
      expect(RootCause::Embassy::Signature.valid?(vector.fetch("signature"), body, secret: reverse_secret)).to be(true)
    end
  end

  it "adds stable diagnostics to every Ruby refusal without changing its wire class" do
    {
      RootCause::Embassy::InvalidRequest => [400, "invalid_request", "INVALID_REQUEST"],
      RootCause::Embassy::SignatureError => [401, "bad_signature", "BAD_SIGNATURE"],
      RootCause::Embassy::ReplayError => [409, "replay", "REPLAY"],
      RootCause::Embassy::SchemaError => [422, "schema_violation", "SCHEMA_VIOLATION"],
      RootCause::Embassy::ResolveError => [502, "resolve_failed", "RESOLVE_FAILED"],
      RootCause::Embassy::HandlerError => [500, "handler_error", "HANDLER_ERROR"],
      RootCause::Embassy::InternalError => [500, "internal_error", "INTERNAL_ERROR"]
    }.each do |klass, (status, wire_class, code)|
      error = klass.new("detail")
      expect(error.status).to eq(status)
      expect(error.wire_payload).to include(class: wire_class, message: "detail", code: code)
      expect(error.hint).not_to be_empty
      expect(error.docs).to end_with("##{code.downcase}")
    end
  end

  it "decodes the answers-only capture fixture" do
    answers = JSON.parse(fixture("analysis/answers.json"))
    expect(answers).not_to have_key("sent")
    expect(answers.fetch("answers")).to eq([{"id" => "country", "values" => ["BE"]}])
  end

  it "replays the chat JWT vector byte-for-byte" do
    jwt = JSON.parse(fixture("chat/jwt_vector.json"))
    claims = JSON.parse(jwt.fetch("claims_json"))
    expect(RootCause::Embassy::Chat.encode(claims, jwt.fetch("secret"))).to eq(jwt.fetch("token"))
    expect(jwt.fetch("token").split(".").first).to eq(RootCause::Embassy::Chat.b64(jwt.fetch("header_json")))
  end

  it "replays the chat widget tag byte-for-byte" do
    jwt = JSON.parse(fixture("chat/jwt_vector.json"))
    config = RootCause::Embassy::Config.new
    config.chat_secret = jwt.fetch("secret")
    config.chat_project = "acme"
    allow(SecureRandom).to receive(:uuid).and_return("88888888-8888-8888-8888-888888888888")

    tag = RootCause::Embassy::Chat.widget_tag_html(
      config: config,
      external_id: "user-8f3",
      kind: "acme_user",
      tenant: "acme",
      origin: "https://app.acme.example",
      locale: "nl",
      color_scheme: "light",
      mode: :page,
      target: "#rc-chat",
      now: Time.at(jwt.fetch("now_unix")),
      ttl: jwt.fetch("ttl_seconds")
    )

    expect(tag).to eq(fixture("chat/widget_tag.html"))
  end
end
