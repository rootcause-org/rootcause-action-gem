# frozen_string_literal: true

require "json"
require "timeout"

module RootCause
  module Embassy
    # Framework-agnostic core of the result route: verify → replay → dispatch →
    # signed ack, fail-closed at every step — the inbound mirror of Runner for the
    # invocation path, on the same reverse-channel secret. Reuses Signature,
    # Replay, Result and Config; ResultRackApp is the thin Rack shell over it.
    class ResultReceiver
      REQUIRED_FIELDS = %w[analysis_id nonce issued_at].freeze

      def initialize(config, nonce_store: nil)
        @config = config
        @nonce_store = nonce_store || Replay::MemoryStore.new
      end

      # @return [Runner::Reply] a signed ack (200 ok) or a signed structured refusal
      def handle(raw_body:, signature:)
        payload = authenticate(raw_body, signature)
        return ack_duplicate(payload) unless fresh?(payload)

        result = dispatch_or_release(payload)
        log(result)
        reply(200, {ok: true})
      rescue Error => e
        # Expected refusals: bad signature, replay, missing fields, unconfigured
        # handler. Still signed so the host can trust the refusal.
        log_refusal(e)
        reply(e.status, {ok: false, error: {class: e.code, message: e.message}})
      rescue => e
        # Fail-closed backstop. A handler exception or any unforeseen condition is a
        # signed, structured 500 — never an unsigned crash, and deliberately NOT an
        # ack: the nonce is released above, so rootcause's redelivery dispatches
        # again — which is exactly why ResultHandler#process is documented idempotent. Message is the class only
        # — an unexpected error's message may carry untrusted input.
        log_unexpected(e)
        reply(500, {ok: false, error: {class: "internal_error", message: e.class.name}})
      end

      private

      # Verify first, parse second: never spend work on an unauthenticated body.
      def authenticate(raw_body, signature)
        unless Signature.valid?(signature, raw_body, secret: @config.secret)
          raise SignatureError, "signature missing or invalid"
        end

        parse(raw_body)
      end

      def parse(raw_body)
        data = JSON.parse(raw_body.to_s)
        raise InvalidRequest, "result must be a JSON object" unless data.is_a?(Hash)

        missing = REQUIRED_FIELDS.reject { |f| present?(data[f]) }
        raise InvalidRequest, "missing field(s): #{missing.join(", ")}" unless missing.empty?

        data
      rescue JSON::ParserError
        raise InvalidRequest, "body is not valid JSON"
      end

      # Freshness on the RESULT route is deliberately asymmetric with the invocation
      # route: rootcause sends `nonce = run_id`, stable across redeliveries of the
      # same result, precisely so the Embassy dedupes. A duplicate is therefore a
      # redelivery to ack (see ack_duplicate), never a refusal. A stale `issued_at`
      # still raises ReplayError → 409: that one bounds how long a captured body
      # stays replayable, and no legitimate redelivery arrives outside the window.
      def fresh?(payload)
        Replay.fresh?(
          issued_at: payload["issued_at"],
          nonce: payload["nonce"],
          clock_skew: @config.clock_skew,
          store: @nonce_store
        )
      end

      # A redelivery inside the window: the first delivery already reached the
      # handler, so re-dispatching would double-process. Ack it exactly like the
      # first — same signed 200 — so the host stops retrying.
      def ack_duplicate(payload)
        @config.logger&.info("[rootcause-result] duplicate analysis_id=#{payload["analysis_id"]} acked (redelivery)")
        reply(200, {ok: true})
      end

      # The nonce is consumed BEFORE dispatch (so two concurrent redeliveries can't
      # both reach the handler). If dispatch then fails, this delivery was never
      # processed, so give the nonce back — otherwise the host's redelivery (same
      # nonce = run_id) would be acked as a duplicate and the result silently lost.
      # A store without #delete keeps the dedupe and loses the retry; inject one
      # that supports removal where that matters.
      def dispatch_or_release(payload)
        dispatch(payload)
      rescue
        @nonce_store.delete(payload["nonce"].to_s) if @nonce_store.respond_to?(:delete)
        raise
      end

      def dispatch(payload)
        result = Result.from_payload(payload)
        handler = build_handler
        # Inline, under the configured timeout — keep handlers a quick write.
        Timeout.timeout(@config.timeout.to_f) { handler.process(result) }
        result
      end

      # Resolve the handler by name on EVERY dispatch so Rails autoload/reload picks
      # up edits (reload-safe). A Class or a ready handler instance is also accepted.
      # Unconfigured or unloadable → fail closed.
      def build_handler
        spec = @config.result_handler
        raise HandlerError, "result_handler is not configured" if spec.nil? || spec.to_s.empty?

        klass = spec.is_a?(String) ? load_const(spec) : spec
        klass.is_a?(Class) ? klass.new : klass
      end

      def load_const(name)
        Object.const_get(name)
      rescue NameError
        raise HandlerError, "result_handler #{name} could not be loaded"
      end

      def reply(status, payload)
        body = JSON.generate(payload)
        Runner::Reply.new(status: status, body: body, signature: Signature.sign(body, secret: @config.secret))
      end

      # Customer-side audit: the run id, metadata KEYS only (never values — they
      # transit rootcause), and ok/decline. Never the secret.
      def log(result)
        return unless @config.logger

        @config.logger.info(
          "[rootcause-result] analysis_id=#{result.analysis_id} " \
          "metadata_keys=#{metadata_keys(result.metadata)} ok=#{result.ok?}"
        )
      end

      def log_refusal(error)
        @config.logger&.warn("[rootcause-result] refused code=#{error.code} msg=#{error.message}")
      end

      def log_unexpected(error)
        @config.logger&.error("[rootcause-result] refused code=internal_error class=#{error.class} msg=#{error.message}")
      end

      def metadata_keys(metadata) = metadata.is_a?(Hash) ? metadata.keys.map(&:to_s).sort : []
      def present?(value) = !value.nil? && value.to_s != ""
    end

    # Thin Rack shell over ResultReceiver — the mirror of RackApp for the result
    # route. Mount it alongside the invocation route:
    #
    #   mount RootCause::Embassy::ResultRackApp.new => RootCause::Embassy.config.result_mount_at
    class ResultRackApp
      SIG_HEADER_ENV = "HTTP_X_WEBHOOK_SIGNATURE"
      JSON_TYPE = "application/json"

      def initialize(receiver: nil)
        @receiver = receiver
      end

      def call(env)
        return method_not_allowed unless env["REQUEST_METHOD"] == "POST"

        raw_body = read_body(env)
        reply = receiver.handle(raw_body: raw_body, signature: env[SIG_HEADER_ENV])
        respond(reply.status, reply.body, reply.signature)
      end

      private

      # Resolve lazily so the app can be constructed at require-time (before the
      # initializer runs) yet still bind to the configured receiver per request.
      def receiver
        @receiver || RootCause::Embassy.result_receiver
      end

      def read_body(env)
        input = env["rack.input"]
        return "" unless input

        body = input.read || ""
        input.rewind if input.respond_to?(:rewind)
        body
      end

      def respond(status, body, signature)
        headers = {
          "content-type" => JSON_TYPE,
          Signature::HEADER => signature
        }
        [status, headers, [body]]
      end

      def method_not_allowed
        [405, {"content-type" => JSON_TYPE, "allow" => "POST"}, [%({"ok":false,"error":{"class":"method_not_allowed","message":"POST required"}})]]
      end
    end
  end
end
