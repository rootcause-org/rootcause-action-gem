# frozen_string_literal: true

require "json"
require "timeout"

module RootCause
  module Embassy
    # The framework-agnostic core: one raw request body + its signature in, one
    # signed JSON reply out. This is the verify → replay → validate → resolve →
    # run → sign pipeline, fail-closed at every step. The Rack shell is a thin
    # adapter over this; a Sinatra/Rack host could call it directly.
    class Runner
      include SignedEndpoint

      # Kept reachable under its historical name: `Runner::Reply` was the public
      # return type of #handle before both endpoints shared one.
      Reply = Embassy::Reply

      TRUSTED_TENANT_FIELDS = %w[tenant_id tenant_slug tenant_scope_value].freeze
      PRINCIPAL_CLAIM_NAME_PATTERN = /\A[a-z][a-z0-9_]*\z/
      REQUIRED_FIELDS = %w[action_id script_digest nonce issued_at].freeze
      TENANT_ID_PATTERN = /\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/i
      TENANT_SLUG_PATTERN = /\A[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?\z/
      NIL_UUID = "00000000-0000-0000-0000-000000000000"

      # Exposed so a thin transport shell (RackApp) can answer plane-disabled before
      # it routes, without reaching into internals.
      attr_reader :config

      def initialize(config, resolver: nil, executor: nil, nonce_store: nil)
        @config = config
        @resolver = resolver || Resolver.new(config)
        @executor = executor || Executor.new(config)
        @nonce_store = nonce_store || Replay::MemoryStore.new
      end

      # @return [Reply]
      #
      # The whole pipeline runs under ONE deadline (config.total_deadline), not just
      # the execution: the host gives the invocation a single 25s shot with no retry,
      # so a script fetch that hangs must still leave us time to answer with a signed
      # result. Timeout.timeout without an exception class raises a non-StandardError
      # internally, so neither the executor's rescue nor the backstop below swallows
      # it — the deadline always wins.
      def handle(raw_body:, signature:)
        return action_plane_disabled unless @config.action_plane_enabled?

        secret = SecretSelector.for_body(@config, raw_body)
        return selector_failure unless secret

        started = clock_ms
        Timeout.timeout(@config.total_deadline.to_f) { handle_within_deadline(raw_body, signature, secret) }
      rescue Timeout::Error
        log_deadline
        reply(200, envelope(deadline_result(started)), secret)
      end

      # GET health is the only action-plane request without a JSON body. In map
      # mode its raw query selects the candidate key, then that exact query is
      # verified before the signed capability response is trusted.
      def health(raw_query:, signature:)
        secret = SecretSelector.for_query(@config, raw_query)
        return Reply.new(status: 404, body: "", signature: nil) unless secret

        # Health stays opaque to an unauthenticated probe, even when its selector
        # happened to name a configured project.
        return Reply.new(status: 404, body: "", signature: nil) unless Signature.valid?(signature, raw_query, secret: secret)

        reply(200, {
          ok: true,
          embassy: "ruby",
          version: VERSION,
          protocol: 1,
          capabilities: ["actions", "dry_run", "analysis_result", "health"]
        }, secret)
      end

      private

      def handle_within_deadline(raw_body, signature, secret)
        invocation = authenticate(raw_body, signature, secret)
        result = run(invocation, secret)
        log(invocation, ok: result.ok, duration_ms: result.duration_ms)
        reply(200, envelope(result), secret)
      rescue Error => e
        # Every expected refusal lands here: bad signature, replay, schema,
        # resolve. Reply is still signed so the host can trust the refusal.
        log_refusal(e, raw_body)
        refusal_reply(e, secret)
      rescue => e
        # Fail-closed backstop. The pipeline raises typed Errors for expected
        # refusals; anything else reaching here is an unforeseen condition (a
        # malformed shape we didn't anticipate, or a gem bug). Still return a
        # signed, structured 500 — never let an unsigned exception escape the
        # handler.
        log_refusal_unexpected(e, raw_body)
        internal_error_reply(e, secret)
      end

      # Same shape the executor produces for its own timeout, so the host sees one
      # failure vocabulary whether the body or the whole invocation ran long.
      def deadline_result(started)
        Executor::Result.new(
          ok: false,
          return_value: nil,
          error: {
            class: "Timeout::Error",
            message: "invocation exceeded #{@config.total_deadline}s total deadline",
            backtrace: []
          },
          stdout: "",
          duration_ms: (clock_ms - started).round
        )
      end

      def log_deadline
        @config.logger&.error("[rootcause-action] refused code=deadline total_deadline=#{@config.total_deadline}")
      end

      # Host-owned fields on top of the shared required-field check. Everything
      # here is trusted-because-signed; params are the schema's business.
      def parse(raw_body)
        data = parse_required(raw_body, noun: "invocation")

        if data["runtime"] && data["runtime"].to_s != "ruby"
          raise InvalidRequest, "unsupported runtime: #{data["runtime"]}"
        end

        # dry_run is a JSON boolean or absent — nothing else. Refuse a non-boolean
        # HERE, at parse time, so a malformed flag can never reach the signed script
        # fetch: "no"/0/"false" are all truthy in Ruby, and guessing which one meant
        # "do not execute" is exactly the ambiguity that would run a live action.
        if data.key?("dry_run") && data["dry_run"] != true && data["dry_run"] != false
          raise InvalidRequest, "dry_run must be a boolean"
        end

        validate_tenant_context!(data)
        validate_principal_context!(data)
        data
      end

      def run(invocation, secret)
        started = clock_ms

        Replay.guard!(
          issued_at: invocation["issued_at"],
          nonce: invocation["nonce"],
          clock_skew: @config.clock_skew,
          store: @nonce_store
        )

        params = Schema.validate!(invocation["params"], invocation["schema"])
        # Resolve runs in dry_run too: it exercises the digest-verified signed
        # fetch, so a dry run surfaces fetch/digest contract problems. Only the
        # executor is skipped.
        script = @resolver.resolve(
          action_id: invocation["action_id"],
          digest: invocation["script_digest"],
          project_id: invocation["project_id"],
          secret: secret
        )

        # Action plane, dry run (rootcause-embassy CONTRACT.md, planes/actions.md):
        # the full verify→replay→schema→resolve pipeline runs but execution is
        # SKIPPED, returning a signed ok:true Result that proves the contract holds
        # with zero side effects. Strictly `== true`; anything else was already
        # refused as invalid_request at parse time.
        if invocation["dry_run"] == true
          return Executor::Result.new(
            ok: true,
            return_value: {"dry_run" => true, "would_execute" => true},
            error: nil,
            stdout: "",
            duration_ms: (clock_ms - started).round
          )
        end

        @executor.run(
          script: script,
          params: params,
          digest: invocation["script_digest"],
          trusted_env: trusted_context_env(invocation)
        )
      end

      def validate_tenant_context!(invocation)
        provided = TRUSTED_TENANT_FIELDS.select { |field| invocation.key?(field) }
        if provided.empty?
          if @config.require_tenant_context && !@config.tenantless_actions.include?(invocation["action_id"])
            raise InvalidRequest, "tenant context is required for this Embassy deployment"
          end
          return
        end

        invalid = provided.reject { |field| invocation[field].is_a?(String) }
        unless invalid.empty?
          raise InvalidRequest, "tenant field(s) must be strings: #{invalid.join(", ")}"
        end
        if provided.any? { |field| invocation[field].include?("\0") }
          raise InvalidRequest, "tenant field(s) must not contain NUL bytes"
        end

        tenant_id = invocation.fetch("tenant_id", "")
        tenant_slug = invocation.fetch("tenant_slug", "")
        tenant_scope_value = invocation.fetch("tenant_scope_value", "")

        if tenant_id.empty? && tenant_slug.empty? && tenant_scope_value.empty?
          raise InvalidRequest, "flat invocation must omit tenant fields"
        end

        if tenant_id.empty?
          raise InvalidRequest, "tenant_id missing for tenant-bound invocation"
        elsif tenant_slug.empty?
          raise InvalidRequest, "tenant_slug missing for tenant-bound invocation"
        elsif !TENANT_ID_PATTERN.match?(tenant_id)
          raise InvalidRequest, "tenant_id must be a UUID"
        elsif tenant_id.casecmp?(NIL_UUID)
          raise InvalidRequest, "tenant_id must not be the nil UUID"
        elsif !TENANT_SLUG_PATTERN.match?(tenant_slug)
          raise InvalidRequest, "tenant_slug is invalid"
        end
      end

      def trusted_tenant_env(invocation)
        {
          "RC_TENANT_ID" => invocation.fetch("tenant_id", ""),
          "RC_TENANT_SLUG" => invocation.fetch("tenant_slug", ""),
          "RC_TENANT_SCOPE_VALUE" => invocation.fetch("tenant_scope_value", "")
        }.reject { |_key, value| value.empty? }.freeze
      end

      def validate_principal_context!(invocation)
        return unless invocation.key?("principal")

        principal = invocation["principal"]
        raise InvalidRequest, "principal must be an object" unless principal.is_a?(Hash)

        %w[kind external_id].each do |field|
          value = principal[field]
          unless value.is_a?(String) && !value.empty?
            raise InvalidRequest, "principal #{field} must be a non-empty string"
          end
          raise InvalidRequest, "principal fields must not contain NUL bytes" if value.include?("\0")
        end

        claims = principal["claims"]
        raise InvalidRequest, "principal claims must be an object" unless claims.is_a?(Hash)

        claims.each do |name, value|
          unless name.is_a?(String) && PRINCIPAL_CLAIM_NAME_PATTERN.match?(name)
            raise InvalidRequest, "principal claim names are invalid"
          end
          validate_principal_claim!(value)
        end
      end

      def validate_principal_claim!(value)
        scalar = value.is_a?(String) || value.is_a?(Integer)
        array = value.is_a?(Array) && (value.all?(String) || value.all?(Integer))
        unless scalar || array
          raise InvalidRequest, "principal claim values must be strings, integers, or homogeneous arrays"
        end

        strings = value.is_a?(Array) ? value.grep(String) : [value].grep(String)
        raise InvalidRequest, "principal fields must not contain NUL bytes" if strings.any? { |item| item.include?("\0") }
      end

      def trusted_context_env(invocation)
        trusted_tenant_env(invocation).merge(trusted_principal_env(invocation)).freeze
      end

      def trusted_principal_env(invocation)
        principal = invocation["principal"]
        return {} unless principal

        claims = principal.fetch("claims")
        {
          "RC_PRINCIPAL_KIND" => principal.fetch("kind"),
          "RC_PRINCIPAL_EXTERNAL_ID" => principal.fetch("external_id")
        }.merge(claims.transform_keys { |name| "RC_PRINCIPAL_CLAIM_#{name.upcase}" }
          .transform_values { |value| value.is_a?(Array) ? JSON.generate(value) : value.to_s })
      end

      def clock_ms = Util.monotonic_ms

      # Key order is not wire contract (the receiver verifies the bytes it got), but
      # emitting the hub's canonical order lets the conformance suite compare our own
      # bytes to the goldens directly instead of only structurally.
      def envelope(result)
        {
          ok: result.ok,
          return_value: result.return_value,
          stdout: result.stdout,
          error: result.error,
          duration_ms: result.duration_ms
        }
      end

      # Customer-side audit: identifiers and shape only. Never the secret, never
      # param values — param KEYS at most.
      def log(invocation, ok:, duration_ms:)
        return unless @config.logger

        @config.logger.info(
          "[rootcause-action] action_id=#{invocation["action_id"]} " \
          "digest=#{invocation["script_digest"]} " \
          "param_keys=#{param_keys(invocation["params"])} " \
          "ok=#{ok} duration_ms=#{duration_ms}"
        )
      end

      def log_refusal(error, raw_body)
        return unless @config.logger

        # Best-effort context without trusting/echoing an unauthenticated body:
        # param KEYS only, and only if it parsed.
        keys = safe_param_keys(raw_body)
        @config.logger.warn("[rootcause-action] refused code=#{error.code} param_keys=#{keys} msg=#{error.message}")
      end

      def log_refusal_unexpected(error, raw_body)
        return unless @config.logger

        keys = safe_param_keys(raw_body)
        # Class name only: CONTRACT.md logging discipline forbids the message text of
        # an unexpected exception — it can carry request values.
        @config.logger.error("[rootcause-action] refused code=internal_error class=#{error.class} param_keys=#{keys}")
      end

      def param_keys(params)
        params.is_a?(Hash) ? params.keys.sort : []
      end

      def safe_param_keys(raw_body)
        data = JSON.parse(raw_body.to_s)
        param_keys(data["params"])
      rescue JSON::ParserError, TypeError
        []
      end
    end
  end
end
