# frozen_string_literal: true

ResolveError = RootCause::Embassy::ResolveError

RSpec.describe RootCause::Embassy::Resolver do
  let(:script) { "{ ok: true }" }
  let(:digest) { Wire.digest_of(script) }
  let(:config) { Wire.config }
  let(:resolver) { described_class.new(config) }

  it "signs the fetch request over the canonical query string" do
    Wire.stub_fetch(script: script)
    resolver.resolve(action_id: "a", digest: digest, project_id: "p1")
    expected_sig = Wire.sign("action_id=a&digest=#{CGI.escape(digest)}&project_id=p1")
    expect(
      a_request(:get, /rootcause\.test/).with(headers: {"X-Webhook-Signature" => expected_sig})
    ).to have_been_made
  end

  it "fetches and digest-verifies on a miss, then serves the second resolve from memory" do
    stub = Wire.stub_fetch(script: script)
    2.times do
      expect(resolver.resolve(action_id: "a", digest: digest, project_id: "p1")).to eq(script)
    end
    expect(stub).to have_been_requested.once
  end

  it "hard-refuses when the fetched body does not match the digest" do
    other = "{ evil: true }"
    # Host claims the requested digest but serves a different body.
    Wire.stub_fetch(script: other, digest: digest)
    expect { resolver.resolve(action_id: "a", digest: digest, project_id: "p1") }.to raise_error(ResolveError, /digest mismatch/)
  end

  it "hard-refuses on a non-2xx response" do
    Wire.stub_fetch(script: script, status: 404)
    expect { resolver.resolve(action_id: "a", digest: digest, project_id: "p1") }.to raise_error(ResolveError, /404/)
  end

  it "hard-refuses when the response signature is invalid" do
    body = JSON.generate("digest" => digest, "script" => script)
    WebMock.stub_request(:get, /rootcause\.test/).to_return(
      status: 200, body: body,
      headers: {"X-Webhook-Signature" => "sha256=forged"}
    )
    expect { resolver.resolve(action_id: "a", digest: digest, project_id: "p1") }.to raise_error(ResolveError, /signature/)
  end

  it "hard-refuses a malformed digest (path-traversal guard)" do
    expect { resolver.resolve(action_id: "a", digest: "sha256:../../etc/passwd", project_id: "p1") }
      .to raise_error(ResolveError, /malformed/)
  end

  describe "disk cache" do
    around do |example|
      Dir.mktmpdir do |dir|
        config.cache_dir = dir
        example.run
      end
    end

    it "writes a verified body to disk and re-reads it on a fresh resolver" do
      stub = Wire.stub_fetch(script: script)
      resolver.resolve(action_id: "a", digest: digest, project_id: "p1")
      expect(stub).to have_been_requested.once

      fresh = described_class.new(config)
      expect(fresh.resolve(action_id: "a", digest: digest, project_id: "p1")).to eq(script)
      # served from disk — no second fetch
      expect(stub).to have_been_requested.once
    end

    it "ignores and re-fetches a tampered disk entry (self-verifying cache)" do
      Wire.stub_fetch(script: script)
      resolver.resolve(action_id: "a", digest: digest, project_id: "p1")

      hex = described_class.hex(digest)
      File.binwrite(File.join(config.cache_dir, "#{hex}.rb"), "{ tampered: true }")

      fresh = described_class.new(config)
      expect(fresh.resolve(action_id: "a", digest: digest, project_id: "p1")).to eq(script)
    end
  end
end
