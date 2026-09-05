# frozen_string_literal: true

require "digest"

RSpec.describe "hub contract conformance" do
  fixture_dir = File.expand_path("../fixtures/contract", __dir__)
  vectors = JSON.parse(File.read(File.join(fixture_dir, "signing_vectors.json")))

  define_method(:fixture_dir) { fixture_dir }
  define_method(:vectors) { vectors }
  def fixture(path) = File.binread(File.join(fixture_dir, path))

  # The same bytes, tagged UTF-8, for comparing against a string the gem produced
  # (JSON.generate returns UTF-8; a binread is ASCII-8BIT and would never ==).
  def utf8_fixture(path) = fixture(path).dup.force_encoding(Encoding::UTF_8)
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
    expect(result.actions.first[:resource_url]).to start_with("http")
    expect(result.actions.first[:resource_url]).not_to eq(result.actions.first[:url])
    expect(result.executed_actions.first).not_to have_key(:resource_url)
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

  # --- own-bytes half of the conformance rule: replay OUR serialization back to
  # the goldens. Verifying the hub's bytes proves we read the wire; producing them
  # proves we write it. Key order is not contract, so where Ruby's serializer
  # legitimately differs we assert structural equality plus a signature over the
  # bytes we actually transmit.
  describe "producing the fixtures from Ruby's own serialization" do
    # The fixtures' reference clock (fixtures/README "Fixed test values"). Every
    # issued_at is this instant, so the suite injects it rather than running the
    # freshness window against wall time.
    let(:contract_clock) { Time.utc(2026, 6, 20) }
    let(:contract_script) { "{ found: true, email: params[:email] }" }
    let(:config) { Wire.config(secret: reverse_secret) }
    let(:runner) { RootCause::Embassy::Runner.new(config) }

    before { allow(Time).to receive(:now).and_return(contract_clock) }

    # Serve the hub's own signed script-fetch response, so the digest-verification
    # path runs against the golden rather than a locally built body.
    def stub_contract_fetch
      body = fixture("actions/fetch_response.json")
      WebMock.stub_request(:get, /rootcause\.test/).to_return(
        status: 200,
        body: body,
        headers: {RootCause::Embassy::Signature::HEADER => RootCause::Embassy::Signature.sign(body, secret: reverse_secret)}
      )
    end

    def invoke(fixture_name)
      raw = fixture(fixture_name)
      runner.handle(raw_body: raw, signature: RootCause::Embassy::Signature.sign(raw, secret: reverse_secret))
    end

    # duration_ms is wall-clock and never reproducible; everything else must match.
    def normalize_duration(json) = json.sub(/"duration_ms":\d+/, %("duration_ms":0))

    it "emits the success envelope byte-for-byte and signs its own bytes" do
      stub_contract_fetch
      reply = invoke("actions/invocation_flat.json")

      expect(reply.status).to eq(200)
      expect(normalize_duration(reply.body)).to eq(normalize_duration(utf8_fixture("actions/result_ok.json")))
      expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: reverse_secret)).to be(true)
    end

    it "emits the dry-run envelope byte-for-byte after performing the signed fetch" do
      stub = stub_contract_fetch
      reply = invoke("actions/invocation_dry_run.json")

      expect(normalize_duration(reply.body)).to eq(normalize_duration(utf8_fixture("actions/result_dry_run.json")))
      expect(stub).to have_been_requested.once
    end

    # WebMock re-normalizes the URI it recorded, so the raw query is asserted the
    # only way that is byte-exact anyway: the signature is computed over it.
    it "signs the script-fetch query in the pinned parameter order" do
      stub_contract_fetch
      invoke("actions/invocation_flat.json")

      expected_query = utf8_fixture("actions/script_fetch_query.txt")
      expect(a_request(:get, /rootcause\.test/).with(
        headers: {RootCause::Embassy::Signature::HEADER => RootCause::Embassy::Signature.sign(expected_query, secret: reverse_secret)}
      )).to have_been_made.once
      requested = WebMock::RequestRegistry.instance.requested_signatures.hash.keys.first.uri
      expect(requested.query_values(Array).map(&:first)).to eq(%w[action_id digest project_id])
    end

    it "emits the health response byte-for-byte once the pinned version is substituted" do
      query = ""
      reply = runner.health(raw_query: query, signature: RootCause::Embassy::Signature.sign(query, secret: reverse_secret))

      pinned = utf8_fixture("actions/health_response.json").sub(/"version":"[^"]+"/, %("version":"#{RootCause::Embassy::VERSION}"))
      expect(reply.body).to eq(pinned)
      expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: reverse_secret)).to be(true)
    end

    it "emits the result-route ack byte-for-byte" do
      receiver = RootCause::Embassy::ResultReceiver.new(Wire.config(secret: reverse_secret, result_handler: Class.new(RootCause::Embassy::ResultHandler) { def process(_result) = nil }))
      raw = fixture("analysis/result_callback.json")
      reply = receiver.handle(raw_body: raw, signature: RootCause::Embassy::Signature.sign(raw, secret: reverse_secret))

      expect(reply.status).to eq(200)
      expect(reply.body).to eq(utf8_fixture("analysis/result_ack.json"))
      expect(RootCause::Embassy::Signature.valid?(reply.signature, reply.body, secret: reverse_secret)).to be(true)
    end

    it "decodes the signed script-fetch response into the digest-verified body" do
      stub_contract_fetch
      script = RootCause::Embassy::Resolver.new(config).resolve(
        action_id: "devise_send_password_reset",
        digest: JSON.parse(fixture("actions/fetch_response.json")).fetch("digest"),
        project_id: "11111111-1111-1111-1111-111111111111"
      )
      expect(script).to eq(contract_script)
    end

    describe "outbound trigger and sent-message bodies" do
      let(:client) { RootCause::Embassy::Client.new(Wire.config(secret: reverse_secret)) }

      def transmitted_body
        WebMock::RequestRegistry.instance.requested_signatures.hash.keys.first.body
      end

      def transmitted_signature
        WebMock::RequestRegistry.instance.requested_signatures.hash.keys.first.headers.fetch("X-Webhook-Signature")
      end

      def expect_signed_over_transmitted_bytes
        expect(RootCause::Embassy::Signature.valid?(transmitted_signature, transmitted_body, secret: reverse_secret)).to be(true)
      end

      it "emits the minimal trigger byte-for-byte" do
        allow(SecureRandom).to receive(:uuid).and_return("contract-nonce-trigger")
        Wire.stub_trigger
        golden = JSON.parse(fixture("analysis/trigger.json"))

        client.start_analysis(
          subject: golden.fetch("subject"),
          body: golden.fetch("body"),
          metadata: golden.fetch("metadata")
        )

        expect(transmitted_body).to eq(utf8_fixture("analysis/trigger.json"))
        expect_signed_over_transmitted_bytes
      end

      # Ruby appends the optional fields after nonce/issued_at, so this one is
      # structurally equal rather than byte-equal — key order is not contract, and
      # the signature is over the bytes we actually sent.
      it "emits a structurally equal principal trigger and signs the bytes it sends" do
        allow(SecureRandom).to receive(:uuid).and_return("contract-nonce-trigger-principal")
        Wire.stub_trigger
        golden = JSON.parse(fixture("analysis/trigger_with_principal.json"))

        client.start_analysis(
          subject: golden.fetch("subject"),
          body: golden.fetch("body"),
          attachments: golden.fetch("attachments"),
          metadata: golden.fetch("metadata"),
          session_id: golden.fetch("session_id"),
          tenant: golden.fetch("tenant"),
          principal: golden.fetch("principal")
        )

        expect(JSON.parse(transmitted_body)).to eq(golden)
        expect(JSON.parse(transmitted_body).keys.sort).to eq(golden.keys.sort)
        expect_signed_over_transmitted_bytes
      end

      it "emits the sent-message capture byte-for-byte" do
        allow(SecureRandom).to receive(:uuid).and_return("contract-nonce-sent-message")
        Wire.stub_sent_message
        golden = JSON.parse(fixture("analysis/sent_message.json"))

        client.capture_sent_message(
          session_id: golden.fetch("session_id"),
          sent_body: golden.dig("sent", "body"),
          sender: golden.dig("sent", "sender"),
          proposed_body: golden.dig("proposed", "body"),
          metadata: golden.fetch("metadata")
        )

        expect(transmitted_body).to eq(utf8_fixture("analysis/sent_message.json"))
        expect_signed_over_transmitted_bytes
      end

      it "emits the answers-only capture byte-for-byte" do
        allow(SecureRandom).to receive(:uuid).and_return("contract-nonce-answers")
        Wire.stub_sent_message
        golden = JSON.parse(fixture("analysis/answers.json"))

        client.capture_sent_message(
          session_id: golden.fetch("session_id"),
          metadata: golden.fetch("metadata"),
          answers: golden.fetch("answers")
        )

        expect(transmitted_body).to eq(utf8_fixture("analysis/answers.json"))
        expect_signed_over_transmitted_bytes
      end
    end
  end

  # conformance.md, action plane: a non-boolean dry_run is a 400 BEFORE any fetch.
  # Ruby truthiness would otherwise read "no" as "yes, dry run" — and worse, the
  # flag was only consulted after the script had already been fetched.
  describe "dry_run is a boolean or absent" do
    let(:config) { Wire.config }
    let(:runner) { RootCause::Embassy::Runner.new(config) }

    def handle(invocation)
      raw = JSON.generate(invocation)
      runner.handle(raw_body: raw, signature: Wire.sign(raw))
    end

    it "refuses a non-boolean dry_run with 400 invalid_request and never fetches the script" do
      stub = Wire.stub_fetch(script: "{ ok: true }")

      reply = handle(Wire.invocation.merge("dry_run" => "no"))

      expect(reply.status).to eq(400)
      expect(JSON.parse(reply.body).dig("error", "class")).to eq("invalid_request")
      expect(stub).not_to have_been_requested
    end

    it "still dry-runs on the JSON boolean true" do
      script = "{ ran: true }"
      Wire.stub_fetch(script: script)

      reply = handle(Wire.invocation(script: script).merge("dry_run" => true))

      expect(reply.status).to eq(200)
      expect(JSON.parse(reply.body)["return_value"]).to eq({"dry_run" => true, "would_execute" => true})
    end
  end

  # decision 17: resource_url is render-only; a non-http(s) value is dropped
  # silently rather than costing the reviewer the whole analysis result.
  describe "proposed action resource_url" do
    def result_with(actions)
      RootCause::Embassy::Result.from_payload("analysis_id" => "r", "actions" => actions)
    end

    it "keeps an absolute https link and drops a non-http(s) one" do
      result = result_with([
        {"id" => "a1", "slug" => "s", "resource_url" => "https://admin.acme.com/users/9f21c4"},
        {"id" => "a2", "slug" => "s", "resource_url" => "javascript:alert(1)"},
        {"id" => "a3", "slug" => "s", "resource_url" => "/users/9f21c4"}
      ])

      expect(result.actions[0][:resource_url]).to eq("https://admin.acme.com/users/9f21c4")
      expect(result.actions[1]).not_to have_key(:resource_url)
      expect(result.actions[1][:id]).to eq("a2")
      expect(result.actions[2]).not_to have_key(:resource_url)
    end

    it "never carries resource_url on an executed action" do
      callback = JSON.parse(fixture("analysis/result_callback.json"))
      result = RootCause::Embassy::Result.from_payload(callback)

      expect(result.executed_actions).not_to be_empty
      result.executed_actions.each { |executed| expect(executed).not_to have_key(:resource_url) }
    end
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
