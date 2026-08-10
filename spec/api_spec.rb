# frozen_string_literal: true

RSpec.describe RootCause::Embassy::Api do
  let(:api) { described_class.new(Wire.api_config) }
  let(:path) { "/api/v1/tenants/yes-events/profile" }
  let(:url) { "#{Wire::API_BASE_URL}#{path}" }

  def stub_call(method: :patch, status: 200, body: "{}", headers: {"content-type" => "application/json"})
    WebMock.stub_request(method, url).to_return(status: status, body: body, headers: headers)
  end

  describe "auth" do
    it "exchanges an rcor_ refresh token and bearers the rcoa_ access token" do
      Wire.stub_token
      stub_call

      expect(api.patch(path, body: {settings: {iban: "BE80"}, source: "embassy"})).to be_ok

      expect(WebMock).to have_requested(:post, Wire::TOKEN_URL).with { |req|
        expect(req.headers["Content-Type"]).to start_with("application/x-www-form-urlencoded")
        expect(CGI.parse(req.body)).to eq(
          "grant_type" => ["refresh_token"],
          "refresh_token" => [Wire::REFRESH_KEY],
          "client_id" => ["rcocl_cli"]
        )
      }
      expect(WebMock).to have_requested(:patch, url).with(
        headers: {"Authorization" => "Bearer #{Wire::ACCESS_TOKEN}"},
        body: JSON.generate("settings" => {"iban" => "BE80"}, "source" => "embassy")
      )
    end

    it "caches the access token across calls and re-exchanges once it nears expiry" do
      Wire.stub_token(expires_in: 3600)
      stub_call(method: :get)

      3.times { api.get(path) }
      expect(WebMock).to have_requested(:post, Wire::TOKEN_URL).once

      # Skew: a token with less than 60s of life left is refreshed early, so an
      # in-flight call never carries a token that dies mid-request.
      RootCause::Embassy::ApiAuth.reset!
      Wire.stub_token(expires_in: 30)
      2.times { api.get(path) }
      expect(WebMock).to have_requested(:post, Wire::TOKEN_URL).times(3)
    end

    it "uses a non-rcor_ key verbatim as the bearer, with no exchange" do
      verbatim = described_class.new(Wire.api_config(api_key: "rcoa_static_bearer"))
      stub_call(method: :get)

      expect(verbatim.get(path)).to be_ok
      expect(WebMock).not_to have_requested(:post, Wire::TOKEN_URL)
      expect(WebMock).to have_requested(:get, url).with(headers: {"Authorization" => "Bearer rcoa_static_bearer"})
    end

    it "caches per key so two Embassies never share a bearer" do
      Wire.stub_token(access_token: "rcoa_first")
      stub_call(method: :get)
      api.get(path)

      other = described_class.new(Wire.api_config(api_key: "rcor_other_credential"))
      Wire.stub_token(access_token: "rcoa_second")
      other.get(path)

      expect(WebMock).to have_requested(:get, url).with(headers: {"Authorization" => "Bearer rcoa_first"})
      expect(WebMock).to have_requested(:get, url).with(headers: {"Authorization" => "Bearer rcoa_second"})
    end

    it "returns a retryable failure (never raises) when the exchange fails" do
      Wire.stub_token(status: 401, body: "nope")

      result = api.patch(path, body: {})
      expect(result.ok?).to be(false)
      expect(result.status).to be_nil
      expect(result.error).to match(/\Aauth: token exchange failed: http_401/)
      expect(result).to be_retryable
    end

    it "burns a refused token and re-exchanges exactly once" do
      Wire.stub_token(access_token: "rcoa_stale")
      WebMock.stub_request(:get, url)
        .to_return(status: 401, body: "{}").then
        .to_return(status: 200, body: '{"ok":true}')

      expect(api.get(path)).to be_ok
      expect(WebMock).to have_requested(:post, Wire::TOKEN_URL).twice
      expect(WebMock).to have_requested(:get, url).twice
    end

    it "does not retry a 401 for a verbatim (non-exchangeable) key" do
      verbatim = described_class.new(Wire.api_config(api_key: "static-bearer"))
      stub_call(method: :get, status: 401, body: '{"error":"unauthorized"}')

      result = verbatim.get(path)
      expect(result.status).to eq(401)
      expect(result).not_to be_retryable
      expect(WebMock).to have_requested(:get, url).once
    end
  end

  describe "verbs and request shape" do
    before { Wire.stub_token }

    it "speaks get/post/patch/put/delete against api_base_url" do
      %i[get post patch put delete].each do |verb|
        stub_call(method: verb)
        expect(api.public_send(verb, path)).to be_ok
        expect(WebMock).to have_requested(verb, url)
      end
    end

    it "sends no body or content-type when body is nil" do
      stub_call(method: :get)
      api.get(path)
      expect(WebMock).to have_requested(:get, url).with { |req| req.body.to_s.empty? && req.headers["Content-Type"].nil? }
    end

    it "appends params as the query string" do
      WebMock.stub_request(:get, "#{url}?limit=2&state=active").to_return(status: 200, body: "{}")
      expect(api.get(path, params: {state: "active", limit: 2})).to be_ok
    end

    it "accepts an absolute URL on the configured origin and refuses another one" do
      stub_call(method: :get)
      expect(api.get(url)).to be_ok
      expect { api.get("https://evil.test/api/v1/tenants") }.to raise_error(ArgumentError, /not on api_base_url/)
    end

    it "raises rather than hiding a misconfiguration in a result" do
      unconfigured = described_class.new(Wire.config)
      expect { unconfigured.get(path) }.to raise_error(ArgumentError, /api_base_url is not configured/)
      expect { api.get("") }.to raise_error(ArgumentError, /api path is required/)
      expect { api.request(:head, path) }.to raise_error(ArgumentError, /unsupported api method/)
    end
  end

  describe "the result struct" do
    before { Wire.stub_token }

    it "parses a JSON body on success" do
      stub_call(status: 200, body: JSON.generate("version" => "7", "settings" => {"iban" => "BE80"}))

      result = api.patch(path, body: {settings: {}})
      expect(result.ok?).to be(true)
      expect(result.status).to eq(200)
      expect(result.body).to eq("version" => "7", "settings" => {"iban" => "BE80"})
      expect(result.field_errors).to be_nil
      expect(result).not_to be_retryable
    end

    it "keeps a non-JSON body as a raw string and an empty body as nil" do
      stub_call(status: 200, body: "plain text", headers: {"content-type" => "text/plain"})
      expect(api.patch(path).body).to eq("plain text")

      stub_call(status: 204, body: "")
      expect(api.patch(path).body).to be_nil
    end

    it "surfaces field_errors and error from a 4xx, permanently" do
      stub_call(status: 400, body: JSON.generate(
        "error" => "validation_failed", "field_errors" => {"payment_provider" => "not a known provider"}
      ))

      result = api.patch(path, body: {settings: {payment_provider: "cash"}})
      expect(result.ok?).to be(false)
      expect(result.status).to eq(400)
      expect(result.error).to eq("validation_failed")
      expect(result.field_errors).to eq("payment_provider" => "not a known provider")
      expect(result).not_to be_retryable
    end

    it "classifies 5xx as retryable and falls back to http_<status> without an error field" do
      stub_call(status: 503, body: "")
      result = api.patch(path)
      expect(result.error).to eq("http_503")
      expect(result).to be_retryable
    end

    it "classifies 429 and 408 as retryable — a whole-fleet sweep rate-limits, it does not break" do
      [429, 408].each do |status|
        stub_call(status: status, body: "")
        expect(api.patch(path)).to be_retryable
      end

      [400, 403, 404, 422].each do |status|
        stub_call(status: status, body: "")
        expect(api.patch(path)).not_to be_retryable
      end
    end

    it "classifies a transport failure as retryable with no status" do
      WebMock.stub_request(:patch, url).to_timeout

      result = api.patch(path, body: {})
      expect(result.ok?).to be(false)
      expect(result.status).to be_nil
      expect(result).to be_retryable
    end

    it "is frozen" do
      stub_call
      expect(api.patch(path)).to be_frozen
    end
  end

  describe ".api_for (a second project's credential)" do
    # rootcause refresh tokens are project-pinned; an app spanning several projects holds one each.
    let(:other_key) { "rcor_support_project_credential" }

    def configure!
      RootCause::Embassy.configure do |c|
        c.secret = Wire::SECRET
        c.fetch_url = Wire::FETCH_URL
        c.logger = nil
        c.api_base_url = Wire::API_BASE_URL
        c.api_key = Wire::REFRESH_KEY
      end
    end

    it "returns a working, independent client that leaves the singleton alone" do
      configure!
      Wire.stub_token(access_token: "rcoa_support")
      stub_call(method: :post)

      other = RootCause::Embassy.api_for(api_base_url: Wire::API_BASE_URL, api_key: other_key)
      expect(other).to be_a(described_class)
      expect(other).not_to be(RootCause::Embassy.api)
      expect(other.post(path, body: {})).to be_ok

      expect(WebMock).to have_requested(:post, Wire::TOKEN_URL)
        .with(body: hash_including("refresh_token" => other_key))
      expect(RootCause::Embassy.config.api_key).to eq(Wire::REFRESH_KEY)
    end

    it "caches its access token separately from the singleton's" do
      configure!
      stub_call(method: :get)

      Wire.stub_token(access_token: "rcoa_singleton")
      RootCause::Embassy.api.get(path)
      Wire.stub_token(access_token: "rcoa_other")
      other = RootCause::Embassy.api_for(api_base_url: Wire::API_BASE_URL, api_key: other_key)
      2.times { other.get(path) }

      # One exchange per credential — neither reused the other's token.
      expect(WebMock).to have_requested(:post, Wire::TOKEN_URL).twice
      expect(WebMock).to have_requested(:get, url).with(headers: {"Authorization" => "Bearer rcoa_singleton"}).once
      expect(WebMock).to have_requested(:get, url).with(headers: {"Authorization" => "Bearer rcoa_other"}).twice
    end

    it "works before .configure and inherits the configured timeouts/logger after it" do
      unconfigured = RootCause::Embassy.api_for(api_base_url: Wire::API_BASE_URL, api_key: "static-bearer")
      Wire.stub_token
      stub_call(method: :get)
      expect(unconfigured.get(path)).to be_ok

      configure!
      RootCause::Embassy.config.http_read_timeout = 42
      inherited = RootCause::Embassy.api_for(api_base_url: Wire::API_BASE_URL, api_key: other_key)
      expect(inherited.instance_variable_get(:@config).http_read_timeout).to eq(42)
    end

    it "validates its arguments exactly as the configure block does" do
      expect { RootCause::Embassy.api_for(api_base_url: Wire::API_BASE_URL, api_key: "") }
        .to raise_error(ArgumentError, /api_key is required/)
      expect { RootCause::Embassy.api_for(api_base_url: nil, api_key: other_key) }
        .to raise_error(ArgumentError, /api_base_url is required/)
      expect { RootCause::Embassy.api_for(api_base_url: "rootcause.test", api_key: other_key) }
        .to raise_error(ArgumentError, /absolute http\(s\) URL/)
    end
  end

  describe "configuration" do
    it "is reachable as Embassy.api once configured, sharing the config" do
      RootCause::Embassy.configure do |c|
        c.secret = Wire::SECRET
        c.fetch_url = Wire::FETCH_URL
        c.logger = nil
        c.api_base_url = Wire::API_BASE_URL
        c.api_key = Wire::REFRESH_KEY
      end
      Wire.stub_token
      stub_call(method: :get)

      expect(RootCause::Embassy.api).to be_a(described_class)
      expect(RootCause::Embassy.api.get(path)).to be_ok
    end

    it "leaves an Embassy that configures no API plane untouched" do
      expect { Wire.config.validate! }.not_to raise_error
      expect(Wire.config.api_configured?).to be(false)
      expect(Wire.api_config.api_configured?).to be(true)
    end

    it "refuses a half-wired or non-absolute API plane at boot" do
      expect { Wire.config(api_key: Wire::REFRESH_KEY).validate! }
        .to raise_error(ArgumentError, /api_base_url is required/)
      expect { Wire.config(api_base_url: Wire::API_BASE_URL).validate! }
        .to raise_error(ArgumentError, /api_key is required/)
      expect { Wire.api_config(api_base_url: "rootcause.test").validate! }
        .to raise_error(ArgumentError, /absolute http\(s\) URL/)
    end
  end
end
