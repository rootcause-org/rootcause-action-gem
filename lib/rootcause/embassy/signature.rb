# frozen_string_literal: true

require "openssl"

module RootCause
  module Embassy
    # HMAC-SHA256 over a raw byte string, formatted as the wire header value
    # `sha256=<hex>`. Used in both directions: verify inbound invocations, sign
    # outbound fetches and results. Always verify-on-raw, never on re-serialized
    # JSON (key ordering / whitespace would change the bytes).
    module Signature
      HEADER = "X-Webhook-Signature"
      PREFIX = "sha256="

      module_function

      # Hex HMAC of `payload` under `secret`, with the `sha256=` wire prefix.
      def sign(payload, secret:)
        raise ArgumentError, "reverse secret is required" if secret.nil? || secret.to_s.strip.empty?

        PREFIX + hexdigest(payload, secret)
      end

      # Constant-time check that `header` matches HMAC(payload, secret).
      # Returns false (never raises) on a nil/blank/malformed header so callers
      # can treat "no signature" and "bad signature" identically — both refuse.
      def valid?(header, payload, secret:)
        return false if header.nil? || header.empty? || secret.nil? || secret.to_s.strip.empty?

        expected = sign(payload, secret: secret)
        secure_compare(expected, header)
      end

      # Constant-time string compare. Prefer OpenSSL's fixed-length compare; it
      # only runs when the lengths already match, so we gate on bytesize first
      # (the length check itself is not secret — both sides are fixed-width hex).
      def secure_compare(a, b)
        return false unless a.bytesize == b.bytesize

        OpenSSL.fixed_length_secure_compare(a, b)
      end

      def hexdigest(payload, secret)
        OpenSSL::HMAC.hexdigest("SHA256", secret, payload.to_s)
      end
    end
  end
end
