# frozen_string_literal: true

require "json"

module RootCause
  module Embassy
    # The Rack half of both mounts, shared verbatim: pull the raw body and the
    # signature header off the request, hand them to the framework-agnostic core,
    # serialize the Reply back. Nothing here knows what the core does — that is the
    # point, so a Sinatra/Rack host (or a new plane) reuses one adapter.
    #
    # A shell supplies `core` (the endpoint object) and may override `route` to
    # answer before the POST check.
    module RackShell
      SIG_HEADER_ENV = "HTTP_X_WEBHOOK_SIGNATURE"
      JSON_TYPE = "application/json"

      def call(env)
        early = route(env)
        return early if early
        return method_not_allowed unless env["REQUEST_METHOD"] == "POST"

        respond(core.handle(raw_body: read_body(env), signature: env[SIG_HEADER_ENV]))
      end

      private

      # Hook: answer before the POST check, or nil to carry on. RackApp uses it for
      # the plane check and the health child.
      def route(_env) = nil

      def read_body(env)
        input = env["rack.input"]
        return "" unless input

        body = input.read || ""
        input.rewind if input.respond_to?(:rewind)
        body
      end

      # One Rack triple for every answer: the exact bytes the signature was computed
      # over, and the signature header only when the reply carries one.
      def respond(reply, extra_headers = {})
        headers = {"content-type" => JSON_TYPE}.merge(extra_headers)
        headers[Signature::HEADER] = reply.signature if reply.signature
        [reply.status, headers, [reply.body]]
      end

      # Deliberately UNSIGNED and outside the signed vocabulary: the liveness floor
      # an operator probes with no side effects.
      def method_not_allowed = respond(Reply.unsigned(MethodNotAllowed.new("POST required")), "allow" => "POST")

      # UNSIGNED by construction: with no action secret configured there is no key
      # to sign with.
      def plane_disabled = respond(Reply.unsigned(ActionPlaneDisabled.new))
    end
  end
end
