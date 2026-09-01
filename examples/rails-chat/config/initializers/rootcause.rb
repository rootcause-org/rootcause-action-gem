# frozen_string_literal: true

RootCause::Embassy.configure do |config|
  config.chat_secret = ENV.fetch("ROOTCAUSE_CHAT_SECRET")
  config.chat_project = ENV.fetch("ROOTCAUSE_CHAT_PROJECT")
  config.logger = Rails.logger
end
