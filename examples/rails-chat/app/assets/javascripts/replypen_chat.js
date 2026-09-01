(function () {
  "use strict";

  var halfLifeMs = 60 * 60 * 1000;

  async function mint() {
    var csrf = document.querySelector('meta[name="csrf-token"]');
    if (!csrf) throw new Error("The Rails CSRF token is missing.");
    var response = await fetch("/replypen/chat/token", {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: { "Accept": "application/json", "X-CSRF-Token": csrf.content }
    });
    var payload = await response.json();
    if (!response.ok || !payload.token) throw new Error("Chat token request failed.");
    return payload;
  }

  function mount(chat) {
    var oldScript = document.getElementById("replypen-loader");
    if (oldScript) oldScript.remove();
    document.getElementById("replypen-chat").replaceChildren();

    var script = document.createElement("script");
    script.id = "replypen-loader";
    script.async = true;
    script.src = chat.baseUrl.replace(/\/$/, "") + "/chat/widget/v1/loader.js?v=2";
    script.dataset.rcProject = chat.project;
    script.dataset.rcToken = chat.token;
    script.dataset.rcMode = "page";
    script.dataset.rcTarget = "#replypen-chat";
    script.addEventListener("load", function () {
      document.getElementById("replypen-status").textContent = "ReplyPen ready.";
      window.setTimeout(function () { boot().catch(showError); }, halfLifeMs);
    });
    script.addEventListener("error", function () { showError(new Error("The ReplyPen loader could not be loaded.")); });
    document.head.appendChild(script);
  }

  async function boot() {
    mount(await mint());
  }

  function showError(error) {
    document.getElementById("replypen-status").textContent = error.message;
    console.error(error);
  }

  boot().catch(showError);
})();
