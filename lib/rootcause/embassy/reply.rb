# frozen_string_literal: true

require "json"

module RootCause
  module Embassy
    # A signed reply, transport-agnostic. `body` is the exact JSON string the
    # `signature` was computed over — send both verbatim (verify-on-raw). Shared by
    # both inbound endpoints so one shell can serialize either one.
    Reply = Struct.new(:status, :body, :signature, keyword_init: true) do
      # A refusal with NO signature: either there is no key to sign with (plane
      # disabled, unknown selector) or the answer sits outside the signed
      # vocabulary (405). Safe — the host never trusts an unverified body.
      def self.unsigned(error)
        new(status: error.status, body: JSON.generate(ok: false, error: error.wire_payload), signature: nil)
      end
    end
  end
end
