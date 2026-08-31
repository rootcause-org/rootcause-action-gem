# frozen_string_literal: true

module RootCause
  module Embassy
    # The mounted HTTP handler — a thin Rack adapter over Runner. All it does is
    # pull the raw body and signature header off the request, hand them to the
    # framework-agnostic core, and serialize the signed Reply back. Mount it in
    # Rails routes (least magic, easy to restrict at the edge):
    #
    #   mount RootCause::Embassy::RackApp.new => RootCause::Embassy.config.mount_at
    #
    # Named RackApp (not Rack) to avoid shadowing the Rack gem's top-level module.
    class RackApp
      SIG_HEADER_ENV = "HTTP_X_WEBHOOK_SIGNATURE"
      JSON_TYPE = "application/json"

      def initialize(runner: nil)
        @runner = runner
      end

      def call(env)
        return health(env) if env["PATH_INFO"] == "/health"
        return method_not_allowed unless env["REQUEST_METHOD"] == "POST"

        raw_body = read_body(env)
        reply = runner.handle(raw_body: raw_body, signature: env[SIG_HEADER_ENV])
        respond(reply.status, reply.body, reply.signature)
      end

      private

      # Resolve lazily so the app can be constructed at require-time (before the
      # initializer runs) yet still bind to the configured runner per request.
      def runner
        @runner || RootCause::Embassy.runner
      end

      def read_body(env)
        input = env["rack.input"]
        return "" unless input

        body = input.read || ""
        input.rewind if input.respond_to?(:rewind)
        body
      end

      def respond(status, body, signature)
        headers = {"content-type" => JSON_TYPE}
        headers[Signature::HEADER] = signature if signature
        [status, headers, [body]]
      end

      def health(env)
        reply = runner.health(raw_query: env["QUERY_STRING"].to_s, signature: env[SIG_HEADER_ENV])
        respond(reply.status, reply.body, reply.signature)
      end

      def method_not_allowed
        [405, {"content-type" => JSON_TYPE, "allow" => "POST"}, [%({"ok":false,"error":{"class":"method_not_allowed","message":"POST required"}})]]
      end
    end
  end
end
