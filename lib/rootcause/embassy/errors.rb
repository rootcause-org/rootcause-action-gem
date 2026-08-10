# frozen_string_literal: true

module RootCause
  module Embassy
    # Base for every refusal the runner raises before/around executing an action.
    #
    # Each carries an HTTP `status` and a stable `code` so the Rack shell can turn
    # it into a signed `{ ok: false, error: { class, message } }` body without a
    # giant case statement. Fail closed: every refusal is one of these.
    class Error < StandardError
      # HTTP status the Rack shell returns for this refusal.
      def status = 500

      # Stable machine code (snake_case) surfaced as the error `class` on the wire.
      def code = "error"
    end

    # Malformed request: unparseable JSON or missing required invocation fields.
    class InvalidRequest < Error
      def status = 400
      def code = "invalid_request"
    end

    # Signature missing or did not verify (constant-time) against the raw body.
    class SignatureError < Error
      def status = 401
      def code = "bad_signature"
    end

    # Replay guard tripped: `issued_at` outside the window or `nonce` already seen.
    class ReplayError < Error
      def status = 409
      def code = "replay"
    end

    # Params failed re-validation against the schema carried in the invocation.
    class SchemaError < Error
      def status = 422
      def code = "schema_violation"
    end

    # Could not produce a digest-verified script body: fetch non-2xx, transport
    # failure, or — the load-bearing one — sha256(body) != script_digest.
    class ResolveError < Error
      def status = 502
      def code = "resolve_failed"
    end

    # The result route could not dispatch: `result_handler` is unconfigured or its
    # named class cannot be loaded. A deploy mistake → signed structured refusal.
    class HandlerError < Error
      def status = 500
      def code = "handler_error"
    end

    # Raised to the CALLER of `start_analysis`, never turned into a signed reply:
    # the analysis trigger got a non-2xx, a malformed response, or a transport
    # failure. The call is the customer's, so we surface it rather than swallow it
    # — the caller decides whether to retry. (A bad/over-cap attachment raises
    # ArgumentError before anything is sent — it is not retryable.)
    class TriggerError < StandardError; end

    # Raised to the CALLER of `capture_sent_message`, never turned into a signed
    # reply: the sent-message capture got a non-2xx, a malformed response, or a
    # transport failure. Fire-and-forget transport, but the call is the customer's
    # — we surface it rather than swallow it, and the caller decides retry/skip.
    # (A blank sent_body/session_id or missing sent_message_url raises ArgumentError
    # before anything is sent — not retryable.)
    class SentMessageError < StandardError; end

    # The API plane could not obtain a bearer: the `rcor_` refresh-token →
    # access-token exchange failed (transport, non-2xx, or a malformed response).
    # Raised only INSIDE Api, which turns it into a retryable Api::Response — the
    # generic API caller never raises for a call outcome.
    class ApiAuthError < StandardError; end
  end
end
