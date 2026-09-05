# frozen_string_literal: true

require_relative "line_cop"

module RuboCop
  module Cop
    module Embassy
      # CONTRACT.md logging discipline: never the message text of an unexpected
      # exception. It can carry request values, so the internal_error log line
      # carries the class name and nothing else.
      class InternalErrorLogMessage < LineCop
        MSG = "Log the exception class only on internal_error — never its message text."
        PATTERN = /code=internal_error.*msg=/

        def offense_for(line)
          MSG if PATTERN.match?(line)
        end
      end
    end
  end
end
