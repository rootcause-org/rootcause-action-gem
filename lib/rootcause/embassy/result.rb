# frozen_string_literal: true

module RootCause
  module Embassy
    # The async analysis result handed to the customer's ResultHandler. Field names
    # are taken VERBATIM from rootcause's webhook.CallbackPayload and ReplyPen's
    # contract so all three products serialize identically. A frozen, symbol-keyed
    # value object — the handler reads a stable, immutable bag.
    #
    # The human-in-the-loop invariant is preserved by the field split:
    # draft / note / attachments / questions are informational (safe to auto-burn
    # into the customer's records); `actions[]` are vetted side-effects rootcause
    # PROPOSES — the customer renders them for a human to click, and they ride back
    # through the gem's existing invocation route. The gem never auto-runs them, so
    # no "autonomous action" feature is needed. Each action is a pass-through hash
    # with { id (action_run uuid), slug (registry action id), label, description,
    # url (single-use token), color }; read fields via symbol keys.
    #
    # `executed_actions[]` is the OPPOSITE of `actions[]` and must never be rendered
    # as a confirm button: those writes ALREADY HAPPENED mid-loop (host autonomy gate
    # was open), so the customer app renders them as outcomes/history. Each is
    # { id (action_run uuid), slug, label, ok (did the write succeed), summary
    # (markdown outcome) }.
    #
    # `questions[]` are the run's clarifying questions: render them in the app's own
    # UI and POST the human's answers back over `capture_sent_message` with the same
    # `session_id`. `delete_ids` (wire key `delete` — a reserved word in Ruby, hence
    # the accessor rename) retracts previously delivered NOTES by their `key`:
    # idempotent (an unknown key is a no-op), may ride alongside a placement, never
    # alongside a decline. A delete-only result places nothing.
    #
    # `draft` and `note` are surfaced as **markdown strings**, not the raw nested
    # nodes: `draft` is the drafted answer's `body_markdown`; `note` is the SUMMARY
    # note's `body_markdown` (rootcause delivers `notes[]` keyed by `key` — one
    # `summary` note plus zero or more other-keyed notes, e.g. a `trace` link note;
    # we surface only the summary). HTML is a fallback only when markdown is absent
    # (the host is migrating notes from `body_html` to `body_markdown`). The run-page
    # link is read programmatically from `metadata[:run_url]`, not parsed out of a
    # note body.
    #
    # `session_id` is the host-managed conversation key — opaque to the gem. Persist
    # it on the record and pass it back to start_analysis to continue the thread; a
    # follow-up then sends only the new message (the host keeps prior history).
    class Result
      attr_reader :analysis_id, :session_id, :project_id, :metadata, :draft, :note, :actions,
        :executed_actions, :questions, :delete_ids, :attachments, :decline

      # The note `key` that carries the human-facing summary. The host
      # (webhook.CallbackNote) discriminates notes by `key` — NoteKeySummary; other
      # keys (e.g. NoteKeyTrace) are surfaced elsewhere (run page via metadata[:run_url])
      # and never burned into `note`.
      SUMMARY_KEY = "summary"

      def initialize(analysis_id:, session_id:, project_id:, metadata:, draft:, note:, actions:,
        executed_actions:, questions:, delete_ids:, attachments:, decline:)
        @analysis_id = analysis_id
        @session_id = session_id
        @project_id = project_id
        @metadata = metadata
        @draft = draft
        @note = note
        @actions = actions
        @executed_actions = executed_actions
        @questions = questions
        @delete_ids = delete_ids
        @attachments = attachments
        @decline = decline
        freeze
      end

      # An analysis that produced output, not a decline.
      def ok? = decline.nil?

      # Build from parsed result JSON (string- or symbol-keyed). Optional scalar
      # fields absent → nil; collection fields absent → empty. Everything is
      # deep-symbolized and frozen.
      def self.from_payload(payload)
        data = deep(payload)
        data = {} unless data.is_a?(Hash)

        new(
          analysis_id: data[:analysis_id],
          session_id: data[:session_id],
          project_id: data[:project_id],
          metadata: data[:metadata] || EMPTY_HASH,
          draft: markdown_of(data[:draft]),
          note: markdown_of(summary_note(data[:notes])),
          actions: data[:actions] || EMPTY_ARRAY,
          executed_actions: data[:executed_actions] || EMPTY_ARRAY,
          questions: data[:questions] || EMPTY_ARRAY,
          delete_ids: data[:delete] || EMPTY_ARRAY,
          attachments: data[:attachments] || EMPTY_ARRAY,
          decline: data[:decline]
        )
      end

      EMPTY_HASH = {}.freeze
      EMPTY_ARRAY = [].freeze

      # The markdown body of a content node ({ body_markdown:, body_html: }), as a
      # string. Prefers `body_markdown`; falls back to `body_html` only when markdown
      # is absent (host migration). nil node or no body → nil.
      def self.markdown_of(node)
        return nil unless node.is_a?(Hash)

        value = node[:body_markdown]
        value = node[:body_html] if blank?(value)
        blank?(value) ? nil : value
      end

      # Pick the single summary note out of `notes[]`. The host discriminates by
      # `key` (webhook.CallbackNote.Key); we accept legacy `kind` as a fallback. When
      # the host marks none explicitly, fall back to the first so a single unkeyed
      # note still surfaces — but an explicit summary always wins over array order, so
      # a later "trace" note can never clobber it. Other-keyed notes are never
      # surfaced here (the run-page link is read from metadata[:run_url]).
      def self.summary_note(notes)
        return nil unless notes.is_a?(Array) && !notes.empty?

        notes.find { |n| note_key(n) == SUMMARY_KEY } || notes.first
      end

      # The discriminator for a note node: prefer `key` (what the host emits), accept
      # legacy `kind`. nil for a non-Hash or an unkeyed note.
      def self.note_key(node)
        return nil unless node.is_a?(Hash)

        (node[:key] || node[:kind])&.to_s
      end

      def self.blank?(value) = value.nil? || value.to_s == ""

      # Deep symbol-keying + freeze. Symbol keys match the documented accessors
      # (e.g. result.metadata[:resource_id]); freezing keeps the bag immutable so a
      # handler can't mutate state that another (redelivered) dispatch would read.
      def self.deep(value)
        case value
        when Hash
          value.each_with_object({}) { |(k, v), h| h[k.to_sym] = deep(v) }.freeze
        when Array
          value.map { |e| deep(e) }.freeze
        when String
          value.frozen? ? value : value.dup.freeze
        else
          value
        end
      end
    end
  end
end
