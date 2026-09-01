# frozen_string_literal: true

require "stringio"

RSpec.describe RootCause::Embassy::RackApp do
  let(:config) { Wire.config }
  let(:runner) { RootCause::Embassy::Runner.new(config) }
  let(:app) { described_class.new(runner: runner) }

  def env_for(method:, body: "", signature: nil)
    {
      "REQUEST_METHOD" => method,
      "rack.input" => StringIO.new(body),
      "HTTP_X_WEBHOOK_SIGNATURE" => signature
    }
  end

  it "handles a POSTed invocation and returns a signed JSON triple" do
    script = "{ ok: true }"
    Wire.stub_fetch(script: script)
    raw = JSON.generate(Wire.invocation(script: script))

    status, headers, body = app.call(env_for(method: "POST", body: raw, signature: Wire.sign(raw)))

    expect(status).to eq(200)
    expect(headers["content-type"]).to eq("application/json")
    joined = body.join
    expect(headers["X-Webhook-Signature"]).to eq(Wire.sign(joined))
    expect(JSON.parse(joined)["ok"]).to be(true)
  end

  it "returns 405 for a non-POST method" do
    status, headers, body = app.call(env_for(method: "GET"))
    expect(status).to eq(405)
    expect(headers["allow"]).to eq("POST")
    expect(JSON.parse(body.join).dig("error", "code")).to eq("METHOD_NOT_ALLOWED")
  end

  it "returns an actionable 503 when a chat-only app mounts the action route" do
    chat_only = RootCause::Embassy::Config.new
    chat_only.chat_secret = "chat-secret"
    chat_only.chat_project = "example-support"
    chat_only.logger = nil
    chat_only.validate!

    status, headers, body = described_class.new(runner: RootCause::Embassy::Runner.new(chat_only))
      .call(env_for(method: "POST", body: "{}"))
    expect(status).to eq(503)
    expect(headers).not_to have_key(RootCause::Embassy::Signature::HEADER)
    expect(JSON.parse(body.join).dig("error", "code")).to eq("ACTION_PLANE_DISABLED")
  end

  it "passes a bad signature through to a signed 401" do
    raw = JSON.generate(Wire.invocation)
    status, = app.call(env_for(method: "POST", body: raw, signature: "sha256=nope"))
    expect(status).to eq(401)
  end

  it "falls back to the globally-configured runner when none is injected" do
    RootCause::Embassy.configure { |c|
      c.secret = Wire::SECRET
      c.fetch_url = Wire::FETCH_URL
      c.logger = nil
    }
    bare = described_class.new
    status, = bare.call(env_for(method: "POST", body: "x", signature: "sha256=nope"))
    expect(status).to eq(401)
  end
end
