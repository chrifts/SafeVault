"use strict";

const output = document.getElementById("output");

// The token lives only in memory (not localStorage), so a script injected
// into another page can't read it, and it disappears when the tab closes.
let token = null;

// Always textContent, never innerHTML: any HTML in a message is shown as text and can't run.
function show(message) {
  output.textContent = message;
}

async function postJson(url, data) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  const body = await response.json().catch(() => ({}));
  return { ok: response.ok, body };
}

document.getElementById("register-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  const { ok, body } = await postJson("/api/auth/register", data);
  show(ok ? "Registered. You can log in now." : body.error ?? "Registration failed.");
});

document.getElementById("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  const { ok, body } = await postJson("/api/auth/login", data);

  if (!ok) {
    show("Invalid username or password.");
    return;
  }

  token = body.token;
  const me = await fetch("/api/users/me", { headers: { Authorization: `Bearer ${token}` } });
  const profile = await me.json();
  show(`Logged in as ${profile.username} (${profile.role}).`);
});
