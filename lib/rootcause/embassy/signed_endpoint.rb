# frozen_string_literal: true

require "json"

module RootCause
  module Embassy
    # What every inbound endpoint on the reverse channel does identically:
    # verify-then-parse, refuse in one signed vocabulary, and never let an
    # unforeseen exception escape unsigned. Runner (invocation) and ResultReceiver
    # (analysis result) differ only in what they do with the parsed payload.
    #
    # An including class declares REQUIRED_FIELDS.
    module SignedEndpoint
      private

      # Verify first, parse second: never spend work on an unauthenticated body.
      def authenticate(raw_body, signature, secret)
        unless Signature.valid?(signature, raw_body, secret: secret)
          raise SignatureError, "signature missing or invalid"
        end

        parse(raw_body)
      end

      # The shared half of `parse`: a JSON object carrying every REQUIRED_FIELDS
      # entry, refused in the endpoint's own noun. Endpoint-specific validation
      # layers on top in `parse`.
      def parse_required(raw_body, noun:)
        data = JSON.parse(raw_body.to_s)
        raise InvalidRequest, "#{noun} must be a JSON object" unless data.is_a?(Hash)

        missing = self.class::REQUIRED_FIELDS.reject { |f| Util.present?(data[f]) }
        raise InvalidRequest, "missing field(s): #{missing.join(", ")}" unless missing.empty?

        data
      rescue JSON::ParserError
        raise InvalidRequest, "body is not valid JSON"
      end

      def reply(status, payload, secret)
        body = JSON.generate(payload)
        Reply.new(status: status, body: body, signature: Signature.sign(body, secret: secret))
      end

      # Expected refusals stay signed so the host can trust the refusal.
      def refusal_reply(error, secret) = reply(error.status, {ok: false, error: error.wire_payload}, secret)

      # Fail-closed backstop for anything that is NOT a typed refusal: a signed,
      # structured 500 rather than an unsigned crash. Message is the class name
      # only — an unexpected error's message may carry untrusted input.
      def internal_error_reply(error, secret)
        internal = InternalError.new(error.class.name)
        reply(internal.status, {ok: false, error: internal.wire_payload}, secret)
      end

      # No usable key means no response signature. Do not parse beyond the
      # selector, touch replay, or leak which projects a shared mount serves.
      def selector_failure = Reply.unsigned(SignatureError.new("signature missing or invalid"))

      def action_plane_disabled = Reply.unsigned(ActionPlaneDisabled.new)
    end
  end
end
