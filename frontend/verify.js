const ETHERSCAN_CONTRACT = "https://sepolia.etherscan.io/address/0x41A730Cbe86B33C9f13c613253e6d077C255b4e9";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function tsToHuman(unixSecs) {
  return new Date(Number(unixSecs) * 1000).toUTCString();
}

function normalize(hex) {
  return hex ? ("0x" + String(hex).replace(/^0x/, "").toLowerCase()) : "";
}

function showError(msg) {
  document.getElementById("result").innerHTML =
    `<div class="error">${escHtml(msg)}</div>`;
}

// ---------------------------------------------------------------------------
// Boot — auto-fill from URL params, wire up button
// ---------------------------------------------------------------------------
(function () {
  const p = new URLSearchParams(window.location.search);
  if (p.get("user_a")) document.getElementById("userA").value = p.get("user_a");
  if (p.get("user_b")) document.getElementById("userB").value = p.get("user_b");

  document.getElementById("btn-verify").addEventListener("click", runVerify);
})();

// ---------------------------------------------------------------------------
// Main verify flow
// ---------------------------------------------------------------------------
async function runVerify() {
  const userA    = document.getElementById("userA").value.trim();
  const userB    = document.getElementById("userB").value.trim();
  const rawText  = document.getElementById("msgText").value;
  const resultEl = document.getElementById("result");
  const spinner  = document.getElementById("spinner");

  resultEl.innerHTML = "";

  if (!userA || !userB) {
    showError("Please enter both usernames.");
    return;
  }
  if (userA.toLowerCase() === userB.toLowerCase()) {
    showError("Please enter two different usernames.");
    return;
  }

  spinner.style.display = "block";

  const url = new URL(`${window.location.origin}/api/verify-public/by-users`);
  url.searchParams.set("user_a", userA);
  url.searchParams.set("user_b", userB);
  if (rawText) url.searchParams.set("text", rawText);

  let data, status;
  try {
    const resp = await fetch(url.toString(), { credentials: "include" });
    status = resp.status;
    data = await resp.json().catch(() => null);
  } catch {
    spinner.style.display = "none";
    showError("Could not reach the server. Check that the API is running.");
    return;
  }

  spinner.style.display = "none";

  if (status === 404) {
    showError("No blockchain record found for this conversation. Either one of the usernames is wrong, the two users have not exchanged messages, or on-chain recording has not completed yet.");
    return;
  }
  if (status === 503) {
    showError("Blockchain not configured on this server.");
    return;
  }
  if (status !== 200) {
    showError(`Server returned ${status}: ${escHtml(data?.detail ?? "Unknown error")}`);
    return;
  }

  const verified  = data.verified;
  const onChain   = normalize(data.on_chain_digest);
  const etherscan = /^https:\/\//.test(data.etherscan_url ?? "") ? data.etherscan_url : ETHERSCAN_CONTRACT;

  const verdictHtml = `<div class="verdict ${verified ? "pass" : "fail"}">
    ${verified ? "✓ PASS — digest matches on-chain record" : "✗ FAIL — digest does not match on-chain record"}
  </div>`;

  resultEl.innerHTML = `
    ${verdictHtml}
    <table class="result-table">
      <tr><td>Participants</td><td>${escHtml(userA)} &amp; ${escHtml(userB)}</td></tr>
      <tr><td>Record index</td><td>${escHtml(String(data.record_index ?? "—"))}</td></tr>
      <tr><td>On-chain digest</td><td><code>${escHtml(onChain)}</code></td></tr>
      <tr><td>Block timestamp</td><td>${escHtml(data.timestamp ? tsToHuman(data.timestamp) : "—")}</td></tr>
      <tr><td>Contract</td>
          <td><a href="${escHtml(etherscan)}" target="_blank" rel="noopener">${escHtml(etherscan)}</a></td></tr>
    </table>`;
}
