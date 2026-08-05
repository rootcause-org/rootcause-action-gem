# frozen_string_literal: true

require_relative "chat"

module RootCause
  module Embassy
    # The Rails/ActionView shell over Chat — the only framework-aware piece of the chat path, kept
    # this thin on purpose (Chat itself stays plain Ruby for Sinatra/Rack/plain-ERB hosts).
    #
    #   # app/helpers/application_helper.rb
    #   include RootCause::Embassy::ChatViewHelper
    #
    #   <%= chat_widget_tag(external_id: current_admin_user.id,
    #                       kind: "kampadmin_admin",
    #                       tenant: ActsAsTenant.current_tenant.slug,
    #                       origin: request.base_url,
    #                       mode: :page, target: "#rc-chat") %>
    module ChatViewHelper
      # Marks the already-escaped snippet safe so ERB emits it verbatim. Escaping happens in Chat
      # (every attribute value), so this never widens what the core produced.
      def chat_widget_tag(**options)
        html = Chat.widget_tag_html(**options)
        html.respond_to?(:html_safe) ? html.html_safe : html # rubocop:disable Rails/OutputSafety
      end
    end
  end
end
