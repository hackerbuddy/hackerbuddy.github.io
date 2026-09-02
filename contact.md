---
layout: default
title: Contact
permalink: /contact/
---

<h1 id="page-heading">Contact</h1>

<p id="page-intro">Interested in working together? Send us a message and we'll be in touch.</p>

<form id="contact-form" class="contact-form" novalidate>
  <input type="hidden" id="form-type" name="type" value="general">

  <div id="urgent-banner" class="urgent-banner" style="display:none;">
    <strong>🚨 Urgent Inquiry</strong> — This message will be flagged as high priority and we will respond as quickly as possible.
  </div>

  <div class="form-group">
    <label for="email">Email</label>
    <input type="email" id="email" name="email" required maxlength="254" autocomplete="email" placeholder="you@example.com">
  </div>

  <div class="form-group">
    <label for="message" id="message-label">Message</label>
    <textarea id="message" name="message" required maxlength="5000" rows="6" placeholder="How can we help?"></textarea>
  </div>

  <div id="form-status" class="form-status" role="alert" aria-live="polite"></div>

  <div class="form-actions">
    <button type="submit" class="btn btn-primary" id="submit-btn">Send Message</button>
    <div class="cf-turnstile" data-sitekey="0x4AAAAAAEkP8bIwhaTPdecN" data-theme="light"></div>
  </div>
</form>

<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<script>
// Detect urgent mode from URL
if (new URLSearchParams(window.location.search).get("urgent") === "1") {
  document.getElementById("form-type").value = "urgent";
  document.getElementById("urgent-banner").style.display = "block";
  document.getElementById("page-heading").textContent = "Under Attack?";
  document.getElementById("page-intro").textContent = "If you\u2019re dealing with an active breach, ongoing exploitation, or a security incident that needs immediate help \u2014 describe what\u2019s happening and how to reach you. We\u2019ll respond as fast as we can.";
  document.getElementById("message-label").textContent = "What\u2019s happening?";
  document.getElementById("message").placeholder = "Describe the incident \u2014 what you\u2019re seeing, when it started, what systems are affected.";
  document.getElementById("submit-btn").textContent = "Send Urgent Request";
  document.getElementById("submit-btn").classList.remove("btn-primary");
  document.getElementById("submit-btn").classList.add("btn-danger");
}

document.getElementById("contact-form").addEventListener("submit", async function(e) {
  e.preventDefault();

  const btn = document.getElementById("submit-btn");
  const status = document.getElementById("form-status");
  const form = e.target;
  const isUrgent = document.getElementById("form-type").value === "urgent";
  const defaultLabel = isUrgent ? "Send Urgent Request" : "Send Message";

  btn.disabled = true;
  btn.textContent = "Sending...";
  status.textContent = "";
  status.className = "form-status";

  const data = new URLSearchParams(new FormData(form));

  try {
    const resp = await fetch("https://www.armorkeeper.com/api/contact", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: data,
    });

    const result = await resp.json();

    if (result.success) {
      status.textContent = isUrgent
        ? "Received. We\u2019re on it."
        : result.message;
      status.className = "form-status form-success";
      form.reset();
      if (isUrgent) document.getElementById("form-type").value = "urgent";
      if (typeof turnstile !== "undefined") turnstile.reset();
    } else {
      status.textContent = result.error || "Something went wrong. Please try again.";
      status.className = "form-status form-error";
    }
  } catch (err) {
    status.textContent = "Network error. Please try again.";
    status.className = "form-status form-error";
  }

  btn.disabled = false;
  btn.textContent = defaultLabel;
});
</script>

