# frozen_string_literal: true

require "json"
require "timeout"
require "stringio"
require "digest"

module RootCause
  module Embassy
    # Runs a digest-verified script body with params bound AS DATA.
    #
    # The body is compiled once per digest into a `lambda { |params| ... }`. Params
    # reach the script only as the lambda argument — a frozen, symbol-keyed hash —
    # never interpolated into the evaluated source. A value like
    # `"; system('rm -rf /')"` is therefore an inert string, not code. The
    # lambda's last expression is its return value; `return` inside the body works
    # because lambdas have method-return semantics.
    #
    # Everything is caught: the hard Timeout backstop, any StandardError, and
    # compile-time ScriptErrors all become a structured `error{class, message,
    # backtrace}`. The run reports failure cleanly; it never guarantees atomicity
    # (Timeout can fire mid-transaction — actions must be idempotent/retry-safe).
    class Executor
      Result = Struct.new(:ok, :return_value, :error, :stdout, :duration_ms, keyword_init: true)
      TENANT_ENV_KEYS = %w[RC_TENANT_ID RC_TENANT_SLUG RC_TENANT_SCOPE_VALUE].freeze
      PRINCIPAL_ENV_KEYS = %w[RC_PRINCIPAL_KIND RC_PRINCIPAL_EXTERNAL_ID].freeze
      PRINCIPAL_CLAIM_ENV_PATTERN = /\ARC_PRINCIPAL_CLAIM_[A-Z][A-Z0-9_]*\z/
      TRUSTED_ENV_KEYS = (TENANT_ENV_KEYS + PRINCIPAL_ENV_KEYS).freeze
      FLAT_TRUSTED_ENV = {}.freeze
      PROCESS_EXECUTION_MUTEX = Mutex.new

      def initialize(config)
        @config = config
        @compiled = {} # hex digest => compiled lambda
        @mutex = Mutex.new
      end

      def run(script:, params:, digest:, trusted_env: FLAT_TRUSTED_ENV)
        stdout = +""
        started = clock_ms
        # Defensive: the body is handed params AS DATA. Schema already deep-freezes
        # the validated hash; freeze here too so the executor is correct on its own.
        params = params.freeze

        return_value = PROCESS_EXECUTION_MUTEX.synchronize do
          with_trusted_environment(trusted_env) do
            capture_stdout(stdout) do
              callable = compile(script, digest)
              Timeout.timeout(@config.timeout.to_f) { callable.call(params) }
            end
          end
        end

        ensure_serializable!(return_value)
        success(return_value, stdout, started)
      rescue Timeout::Error
        failure("Timeout::Error", "action exceeded #{@config.timeout}s timeout", [], stdout, started)
      rescue ScriptError, StandardError => e
        failure(e.class.name, e.message.to_s, Array(e.backtrace), stdout, started)
      end

      private

      # ENV and $stdout are process-global, so action execution must be serialized
      # while trusted host context is installed to prevent cross-run context bleed.
      def with_trusted_environment(values)
        unless values.keys.all? { |key| trusted_env_key?(key) } && values.values.all? { |value| value.is_a?(String) && !value.include?("\0") }
          raise ArgumentError, "trusted_env may contain only trusted NUL-free string fields"
        end

        managed_keys = (TRUSTED_ENV_KEYS + values.keys + ENV.keys.grep(/\ARC_PRINCIPAL_/)).uniq
        previous = managed_keys.to_h { |key| [key, [ENV.key?(key), ENV[key]]] }
        managed_keys.each { |key| ENV.delete(key) }
        values.each { |key, value| ENV[key] = value }
        yield
      ensure
        previous&.each do |key, (present, value)|
          present ? ENV[key] = value : ENV.delete(key)
        end
      end

      def trusted_env_key?(key)
        TRUSTED_ENV_KEYS.include?(key) || PRINCIPAL_CLAIM_ENV_PATTERN.match?(key)
      end

      def compile(script, digest)
        hex = Resolver.hex(digest)
        @mutex.synchronize do
          @compiled[hex] ||= build_lambda(script, hex)
        end
      end

      # lineno 0 means "lambda do |params|" is line 0, so the body's first line is
      # line 1 — backtraces then carry the script's own line numbers.
      def build_lambda(script, hex)
        source = "lambda do |params|\n#{script}\nend"
        eval(source, sandbox_binding, "rootcause-action(#{hex})", 0) # standard:disable Security/Eval
      end

      # A fresh top-level-ish binding: constant lookup resolves app constants
      # (User, etc.) but no local variables from the gem leak into the script.
      def sandbox_binding
        TOPLEVEL_BINDING.dup
      end

      def ensure_serializable!(value)
        JSON.generate(value)
      rescue => e
        raise NonSerializableResult, "return value is not JSON-serializable: #{e.message}"
      end

      def success(return_value, stdout, started)
        Result.new(
          ok: true,
          return_value: return_value,
          error: nil,
          stdout: finalize_stdout(stdout),
          duration_ms: elapsed_ms(started)
        )
      end

      def failure(klass, message, backtrace, stdout, started)
        Result.new(
          ok: false,
          return_value: nil,
          error: {
            class: klass,
            message: message,
            backtrace: backtrace.first(@config.max_backtrace_lines)
          },
          stdout: finalize_stdout(stdout),
          duration_ms: elapsed_ms(started)
        )
      end

      # Capture the action's $stdout. CAVEAT: $stdout is process-global, so under a
      # multi-threaded server this also intercepts (and isolates from the real
      # stream) any concurrent thread's output for the duration of the run. v1
      # accepts this; disable via `config.capture_stdout = false` where it matters.
      def capture_stdout(buffer)
        return yield unless @config.capture_stdout

        original = $stdout
        sink = StringIO.new(buffer)
        $stdout = sink
        begin
          yield
        ensure
          $stdout = original
        end
      end

      def finalize_stdout(buffer)
        return "" if buffer.nil? || buffer.empty?

        max = @config.max_stdout_bytes
        out = (buffer.bytesize > max) ? buffer.byteslice(0, max) : buffer
        out.dup.force_encoding(Encoding::UTF_8).scrub
      end

      def elapsed_ms(started) = (clock_ms - started).round
      def clock_ms = Util.monotonic_ms
    end

    # The action ran but returned something JSON can't represent — treated as a
    # failed run, not a crash.
    class NonSerializableResult < StandardError; end
  end
end
