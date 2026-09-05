# frozen_string_literal: true

require "rubocop"

module RuboCop
  module Cop
    module Embassy
      # Base for this repo's house cops. They are deliberately LINE checks, not AST
      # checks: each one guards a single invariant from the contract hub
      # (rootcause-embassy) that is already stated as a literal in the source — a
      # header name, a wire class, a log key. An AST cop would be more machinery
      # than the invariant is worth, and these must stay cheap enough that nobody
      # is tempted to delete them.
      #
      # Subclasses implement `offense_for(line)` and return a message, or nil.
      class LineCop < Base
        def on_new_investigation
          processed_source.lines.each_with_index do |line, index|
            next if line.lstrip.start_with?("#")

            message = offense_for(line)
            next unless message

            add_offense(processed_source.buffer.line_range(index + 1), message: message)
          end
        end

        def offense_for(_line) = nil
      end
    end
  end
end
