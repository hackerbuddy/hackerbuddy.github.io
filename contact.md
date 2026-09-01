---
layout: default
title: Contact
permalink: /contact/
---

<h1>Contact</h1>

<p>Interested in working together? Send us a message and we'll be in touch.</p>

<form id="contact-form" class="contact-form" novalidate>
  <div class="form-group">
    <label for="name">Name</label>
    <input type="text" id="name" name="name" required maxlength="200" autocomplete="name" placeholder="Your name">
  </div>

  <div class="form-group">
    <label for="email">Email</label>
    <input type="email" id="email" name="email" required maxlength="254" autocomplete="email" placeholder="you@example.com">
  </div>

  <div class="form-group">
    <label for="message">Message</label>
    <textarea id="message" name="message" required maxlength="5000" rows="6" placeholder="How can we help?"></textarea>
  </div>

  <div class="cf-turnstile" data-sitekey="0x4AAAAAAEkP8bIwhaTPdecN" data-theme="light"></div>

  <div id="form-status" class="form-status" role="alert" aria-live="polite"></div>

  <button type="submit" class="btn btn-primary" id="submit-btn">Send Message</button>
</form>

<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<script>
document.getElementById("contact-form").addEventListener("submit", async function(e) {
  e.preventDefault();

  const btn = document.getElementById("submit-btn");
  const status = document.getElementById("form-status");
  const form = e.target;

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
      status.textContent = result.message;
      status.className = "form-status form-success";
      form.reset();
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
  btn.textContent = "Send Message";
});
</script>

---

For vulnerability disclosure inquiries, include the program name and report reference in your message, or email [security@armorkeeper.com](mailto:security@armorkeeper.com) directly.
