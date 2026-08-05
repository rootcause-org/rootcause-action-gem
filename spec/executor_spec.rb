# frozen_string_literal: true

RSpec.describe RootCause::Embassy::Executor do
  let(:config) { Wire.config(timeout: 2) }
  let(:executor) { described_class.new(config) }

  def run(script, params: {})
    executor.run(script: script, params: params, digest: Wire.digest_of(script))
  end

  it "returns the last expression as the JSON-able return value" do
    result = run("a = 1\n{ sum: a + 2 }")
    expect(result.ok).to be(true)
    expect(result.return_value).to eq({sum: 3})
    expect(result.duration_ms).to be >= 0
  end

  it "binds params as a frozen, symbol-keyed hash" do
    result = run("{ got: params[:name], frozen: params.frozen? }", params: {name: "ann"})
    expect(result.return_value).to eq({got: "ann", frozen: true})
  end

  it "installs only trusted tenant environment for the run and restores the process environment" do
    original = RootCause::Embassy::Executor::TRUSTED_ENV_KEYS.to_h do |key|
      [key, [ENV.key?(key), ENV[key]]]
    end
    ENV["RC_TENANT_ID"] = "stale-process-value"
    trusted_env = {
      "RC_TENANT_ID" => Wire::TENANT_ID,
      "RC_TENANT_SLUG" => Wire::TENANT_SLUG,
      "RC_TENANT_SCOPE_VALUE" => Wire::TENANT_SCOPE_VALUE
    }

    result = executor.run(
      script: "ENV.values_at(*%w[RC_TENANT_ID RC_TENANT_SLUG RC_TENANT_SCOPE_VALUE])",
      params: {},
      digest: Wire.digest_of("ENV.values_at(*%w[RC_TENANT_ID RC_TENANT_SLUG RC_TENANT_SCOPE_VALUE])"),
      trusted_env: trusted_env
    )

    expect(result.return_value).to eq([Wire::TENANT_ID, Wire::TENANT_SLUG, Wire::TENANT_SCOPE_VALUE])
    expect(ENV["RC_TENANT_ID"]).to eq("stale-process-value")
  ensure
    original&.each do |key, (present, value)|
      present ? ENV[key] = value : ENV.delete(key)
    end
  end

  it "restores trusted tenant environment after an action raises" do
    original_present = ENV.key?("RC_TENANT_SLUG")
    original_value = ENV["RC_TENANT_SLUG"]
    ENV.delete("RC_TENANT_SLUG")
    trusted_env = {
      "RC_TENANT_ID" => Wire::TENANT_ID,
      "RC_TENANT_SLUG" => Wire::TENANT_SLUG,
      "RC_TENANT_SCOPE_VALUE" => Wire::TENANT_SCOPE_VALUE
    }

    result = executor.run(
      script: "raise ENV.fetch('RC_TENANT_SLUG')",
      params: {},
      digest: Wire.digest_of("raise ENV.fetch('RC_TENANT_SLUG')"),
      trusted_env: trusted_env
    )

    expect(result.error[:message]).to eq(Wire::TENANT_SLUG)
    expect(ENV).not_to have_key("RC_TENANT_SLUG")
  ensure
    original_present ? ENV["RC_TENANT_SLUG"] = original_value : ENV.delete("RC_TENANT_SLUG")
  end

  it "supports an early `return` from the body (lambda semantics)" do
    script = "return { early: true } if params[:bail]\n{ early: false }"
    expect(run(script, params: {bail: true}).return_value).to eq({early: true})
    expect(run(script, params: {bail: false}).return_value).to eq({early: false})
  end

  it "treats a param value that looks like code as an inert string" do
    # If this were interpolated into source it would raise/execute; as data it
    # is just a string the script can read back.
    payload = %(; system('touch /tmp/rootcause-pwned'); ")
    result = run("{ echoed: params[:x] }", params: {x: payload})
    expect(result.ok).to be(true)
    expect(result.return_value).to eq({echoed: payload})
    expect(File).not_to exist("/tmp/rootcause-pwned")
  end

  it "kills a hanging body with the hard timeout and returns a structured error" do
    result = run("sleep 5\n{ done: true }")
    expect(result.ok).to be(false)
    expect(result.error[:class]).to eq("Timeout::Error")
    expect(result.return_value).to be_nil
  end

  it "captures a raised exception as error{class, message, backtrace}" do
    result = run("raise ArgumentError, 'boom'")
    expect(result.ok).to be(false)
    expect(result.error[:class]).to eq("ArgumentError")
    expect(result.error[:message]).to eq("boom")
    expect(result.error[:backtrace]).to be_an(Array)
  end

  it "reports backtrace frames carrying the script's own line numbers" do
    result = run("a = 1\nraise 'x'") # raise is on script line 2
    expect(result.error[:backtrace].first).to match(/rootcause-action.*:2/)
  end

  it "fails the run when the return value is not JSON-serializable" do
    result = run("0.0 / 0.0") # NaN — JSON.generate refuses it by default
    expect(result.ok).to be(false)
    expect(result.error[:class]).to eq("RootCause::Embassy::NonSerializableResult")
  end

  it "captures stdout when enabled" do
    result = run("puts 'hello'\n{ ok: true }")
    expect(result.stdout).to eq("hello\n")
  end

  it "truncates stdout to max_stdout_bytes" do
    config.max_stdout_bytes = 10
    result = run("print 'x' * 100\n{ ok: true }")
    expect(result.stdout.bytesize).to eq(10)
  end

  it "omits stdout capture when disabled" do
    config.capture_stdout = false
    result = run("puts 'hello'\n{ ok: true }")
    expect(result.stdout).to eq("")
  end

  it "restores $stdout even when the body raises" do
    original = $stdout
    run("puts 'x'\nraise 'boom'")
    expect($stdout).to be(original)
  end

  it "captures a SyntaxError in the body as a failed run, not a crash" do
    result = run("this is not ; valid ruby )(")
    expect(result.ok).to be(false)
    expect(result.error[:class]).to match(/SyntaxError/)
  end
end
