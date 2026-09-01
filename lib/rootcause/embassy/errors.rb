# frozen_string_literal: true

module RootCause
  module Embassy
    # Stable customer-facing failure. Action/result subclasses also carry the
    # closed wire class and HTTP status used by signed refusals.
    class Error < ArgumentError
      DOCS_BASE_URL = "https://github.com/rootcause-org/rootcause-embassy/blob/main/docs/integrator/errors.md#"

      class << self
        attr_reader :status, :wire_class, :diagnostic_code, :diagnostic_hint

        def diagnostic(code:, hint:, status: nil, wire_class: nil)
          @status = status
          @wire_class = wire_class
          @diagnostic_code = code
          @diagnostic_hint = hint
        end

        def public(code, hint, message = nil)
          detail = message ? "#{message}. " : ""
          new("#{code.downcase}: #{detail}#{hint}", code: code, hint: hint)
        end

        def docs_url(code)
          "#{DOCS_BASE_URL}#{code.to_s.downcase}"
        end
      end

      attr_reader :status, :wire_class, :code, :hint, :docs

      def initialize(message = nil, code: nil, hint: nil, docs: nil, status: nil, wire_class: nil)
        @status = status || self.class.status
        @wire_class = wire_class || self.class.wire_class
        @code = code || self.class.diagnostic_code
        @hint = hint || self.class.diagnostic_hint
        @docs = docs || self.class.docs_url(@code)
        super(message || @hint)
      end

      def wire_payload
        {class: wire_class, message: message, code: code, hint: hint, docs: docs}
      end
    end

    # Malformed request: unparseable JSON or missing required invocation fields.
    class InvalidRequest < Error
      diagnostic status: 400, wire_class: "invalid_request", code: "INVALID_REQUEST",
        hint: "Compare the signed action request with CONTRACT.md and fix the invalid field."
    end

    # Signature missing or did not verify (constant-time) against the raw body.
    class SignatureError < Error
      diagnostic status: 401, wire_class: "bad_signature", code: "BAD_SIGNATURE",
        hint: "Verify ROOTCAUSE_ACTION_SECRET and sign the exact transmitted bytes."
    end

    # Replay guard tripped: `issued_at` outside the window or `nonce` already seen.
    class ReplayError < Error
      diagnostic status: 409, wire_class: "replay", code: "REPLAY",
        hint: "Use a fresh nonce and current issued_at; never retry an action whose outcome is uncertain."
    end

    # Params failed re-validation against the schema carried in the invocation.
    class SchemaError < Error
      diagnostic status: 422, wire_class: "schema_violation", code: "SCHEMA_VIOLATION",
        hint: "Match params to the approved schema and keep trusted context out of params."
    end

    # Could not produce a digest-verified script body: fetch non-2xx, transport
    # failure, or — the load-bearing one — sha256(body) != script_digest.
    class ResolveError < Error
      diagnostic status: 502, wire_class: "resolve_failed", code: "RESOLVE_FAILED",
        hint: "Check ROOTCAUSE_FETCH_URL and run a dry run; never bypass signature or digest verification."
    end

    # The result route could not dispatch: `result_handler` is unconfigured or its
    # named class cannot be loaded. A deploy mistake → signed structured refusal.
    class HandlerError < Error
      diagnostic status: 500, wire_class: "handler_error", code: "HANDLER_ERROR",
        hint: "Configure an idempotent result handler and verify it with the analysis result fixture."
    end

    class InternalError < Error
      diagnostic status: 500, wire_class: "internal_error", code: "INTERNAL_ERROR",
        hint: "Upgrade the Embassy, rerun conformance, then escalate with a redacted doctor bundle."
    end

    class MethodNotAllowed < Error
      diagnostic status: 405, wire_class: "method_not_allowed", code: "METHOD_NOT_ALLOWED",
        hint: "Send POST to the action mount, or GET to its health child."
    end

    class ActionPlaneDisabled < Error
      diagnostic status: 503, wire_class: "action_plane_disabled", code: "ACTION_PLANE_DISABLED",
        hint: "Configure ROOTCAUSE_ACTION_SECRET and ROOTCAUSE_FETCH_URL before using actions or analysis."
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
