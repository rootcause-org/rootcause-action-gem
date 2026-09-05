# frozen_string_literal: true

require "digest"

# Test helpers that play the rootcause host: build/sign invocations and stub the
# script-by-digest endpoint exactly as the gem expects to verify it.
module Wire
  SECRET = "test-reverse-channel-secret"
  PROJECT_ID = "00000000-0000-0000-0000-000000000000"
  TENANT_ID = "11111111-1111-1111-1111-111111111111"
  TENANT_SLUG = "acme"
  TENANT_SCOPE_VALUE = "tenant-acme"
  FETCH_URL = "https://rootcause.test/actions/script"
  TRIGGER_URL = "https://rootcause.test/analyses/test-project"
  SENT_MESSAGE_URL = "https://rootcause.test/analyses/test-project/sent-message"

  module_function

  def sign(payload, secret: SECRET)
    RootCause::Embassy::Signature.sign(payload, secret: secret)
  end

  def digest_of(script)
    "sha256:#{Digest::SHA256.hexdigest(script)}"
  end

  # A valid invocation body (Ruby hash). Override any field via kwargs.
  def invocation(script: "{ ok: true }", **overrides)
    {
      "action_id" => "devise_send_password_reset",
      "script_digest" => digest_of(script),
      "params" => {},
      "schema" => {},
      "runtime" => "ruby",
      "project_id" => PROJECT_ID,
      "tenant_id" => TENANT_ID,
      "tenant_slug" => TENANT_SLUG,
      "tenant_scope_value" => TENANT_SCOPE_VALUE,
      "nonce" => "nonce-#{rand(1_000_000)}",
      "issued_at" => Time.now.utc.iso8601
    }.merge(overrides)
  end

  # Stub the host's script-fetch endpoint to return a signed body for `script`.
  # By default the returned digest is the true sha256 — pass `digest:` to forge.
  def stub_fetch(script:, digest: nil, action_id: "devise_send_password_reset", status: 200)
    digest ||= digest_of(script)
    body = JSON.generate(
      "action_id" => action_id,
      "digest" => digest,
      "script" => script,
      "runtime" => "ruby"
    )
    WebMock.stub_request(:get, /rootcause\.test/).to_return(
      status: status,
      body: body,
      headers: {RootCause::Embassy::Signature::HEADER => sign(body)}
    )
  end

  # --- API plane ---
  API_BASE_URL = "https://rootcause.test"
  TOKEN_URL = "https://rootcause.test/oauth/token"
  REFRESH_KEY = "rcor_machine_credential"
  ACCESS_TOKEN = "rcoa_access_token"

  def api_config(**overrides)
    config(api_base_url: API_BASE_URL, api_key: REFRESH_KEY, **overrides)
  end

  # Stub the host's OAuth token endpoint (the rcor_ → rcoa_ exchange).
  def stub_token(access_token: ACCESS_TOKEN, expires_in: 3600, status: 200, body: nil)
    WebMock.stub_request(:post, TOKEN_URL).to_return(
      status: status,
      body: body || JSON.generate("access_token" => access_token, "expires_in" => expires_in, "token_type" => "Bearer"),
      headers: {"content-type" => "application/json"}
    )
  end

  # --- embedded chat ---
  # The chat key is the project's webhook_secret — deliberately NOT the reverse-channel SECRET above.
  CHAT_SECRET = "test-project-webhook-secret"
  CHAT_PROJECT = "acme-support"
  CHAT_BASE_URL = "https://chat.rootcause.test"
  CHAT_ORIGIN = "https://admin.acme.example"

  # Verify + parse a compact JWS exactly as the rootcause host does: HMAC over the EXACT transmitted
  # `header.payload` segments, then JSON. Raises when the signature does not verify.
  def decode_jwt(token, secret: CHAT_SECRET)
    header_b64, payload_b64, sig_b64 = token.split(".")
    expected = RootCause::Embassy::Chat.b64(
      OpenSSL::HMAC.digest("SHA256", secret, "#{header_b64}.#{payload_b64}")
    )
    raise "embed token signature does not verify" unless sig_b64 == expected

    [JSON.parse(unb64(header_b64)), JSON.parse(unb64(payload_b64))]
  end

  def unb64(segment)
    padded = segment.tr("-_", "+/")
    padded += "=" * ((4 - (padded.length % 4)) % 4)
    padded.unpack1("m")
  end

  def chat_config(**overrides)
    config(chat_secret: CHAT_SECRET, chat_project: CHAT_PROJECT, chat_base_url: CHAT_BASE_URL, **overrides)
  end

  def config(**overrides)
    cfg = RootCause::Embassy::Config.new
    cfg.secret = SECRET
    cfg.fetch_url = FETCH_URL
    cfg.trigger_url = TRIGGER_URL
    cfg.sent_message_url = SENT_MESSAGE_URL
    cfg.logger = nil
    cfg.cache_dir = nil # memory-only in tests; no tmp pollution
    overrides.each { |k, v| cfg.public_send("#{k}=", v) }
    cfg
  end

  # --- async analysis ---

  # Stub the host's trigger endpoint, returning the documented 202 with the run id
  # and the host-minted/echoed session_id.
  def stub_trigger(analysis_id: "analysis-uuid-1", session_id: "session-uuid-1", status: 202)
    WebMock.stub_request(:post, TRIGGER_URL).to_return(
      status: status,
      body: JSON.generate("analysis_id" => analysis_id, "session_id" => session_id, "status" => "queued"),
      headers: {"content-type" => "application/json"}
    )
  end

  # Stub the host's sent-message route, returning a 2xx with the persisted row id.
  def stub_sent_message(id: "sent-msg-1", status: 200)
    WebMock.stub_request(:post, SENT_MESSAGE_URL).to_return(
      status: status,
      body: JSON.generate("sent_message_id" => id),
      headers: {"content-type" => "application/json"}
    )
  end

  # A valid result body (Ruby hash) as rootcause POSTs to the result route.
  # Override or add CallbackPayload fields via kwargs.
  def result(**overrides)
    {
      "analysis_id" => "analysis-uuid-1",
      "session_id" => "session-uuid-1",
      "metadata" => {"resource_type" => "SupportTicket", "resource_id" => "42"},
      "draft" => {"body_markdown" => "Hi there", "body_html" => "<p>Hi there</p>"},
      "notes" => [
        {"kind" => "summary", "body_markdown" => "Summary. [run trace](https://rc/runs/1)", "body_html" => "<p>Summary.</p>"},
        {"kind" => "widget", "body_markdown" => "widget detail", "body_html" => "<p>widget</p>"}
      ],
      "actions" => [],
      "attachments" => [],
      "decline" => nil,
      "nonce" => "result-nonce-#{rand(1_000_000)}",
      "issued_at" => Time.now.utc.iso8601
    }.merge(overrides)
  end
end
