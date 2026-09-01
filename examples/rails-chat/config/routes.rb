Rails.application.routes.draw do
  get "/replypen/chat", to: "replypen_chat#show"
  post "/replypen/chat/token", to: "replypen_chat#token"
end
