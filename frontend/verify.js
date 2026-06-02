  // ---------------------------------------------------------------------------
  // Configuration — change API_BASE to your server's address if needed
  // ---------------------------------------------------------------------------
  const API_BASE = window.location.origin;

  // ---------------------------------------------------------------------------
  // Local keccak256 using ethers.js (no server involvement)
  // ---------------------------------------------------------------------------
  function localKeccak(text) {
    return ethers.keccak256(ethers.toUtf8Bytes(text));
  }

  // ---------------------------------------------------------------------------
  // Render helpers
  // ---------------------------------------------------------------------------
  function showError(msg) {
    document.getElementById("result").innerHTML =
      `<div class="error">${escHtml(msg)}</div>`;
  }

  function escHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function tsToHuman(unixSecs) {
    return new Date(unixSecs * 1000).toUTCString();
  }

  function normalize(hex) {
    // Ensure consistent 0x-prefixed lowercase for comparison
    return hex ? ("0x" + hex.replace(/^0x/, "").toLowerCase()) : "";
  }

  // ---------------------------------------------------------------------------
  // Main verify flow
  // ---------------------------------------------------------------------------
  async function runVerify() {
    const convId  = document.getElementById("convId").value.trim();
    const rawText = document.getElementById("msgText").value;
    const resultEl = document.getElementById("result");
    const spinner  = document.getElementById("spinner");

    resultEl.innerHTML = "";

    if (!convId) {
      showError("Please enter a Conversation ID.");
      return;
    }

    // Compute local hash before touching the network
    const localHash = rawText ? normalize(localKeccak(rawText)) : null;

    // Build request URL
    const url = new URL(`${API_BASE}/public/verify/${encodeURIComponent(convId)}`);
    if (rawText) url.searchParams.set("text", rawText);

    spinner.style.display = "block";
    let data, status;
    try {
      // credentials:"include" sends the session cookie — the endpoint now
      // requires authentication and verifies the caller is a participant.
      const resp = await fetch(url.toString(), { method: "GET", credentials: "include" });
      status = resp.status;
      data = await resp.json().catch(() => null);
    } catch (_) {
      spinner.style.display = "none";
      showError("Could not reach the server. Check that the API is running and the URL is correct.");
      return;
    }
    spinner.style.display = "none";

    // Error responses
    if (status === 404) {
      showError("No blockchain record found for this conversation. Either the conversation does not exist or on-chain recording has not completed yet.");
      return;
    }
    if (status === 503) {
      showError("Blockchain not configured on this server. The PRIVATE_KEY / CONTRACT_ADDRESS environment variables are not set.");
      return;
    }
    if (status !== 200) {
      const detail = data?.detail ?? "Unknown error";
      showError(`Server returned ${status}: ${detail}`);
      return;
    }

    // Success — render result
    const verified    = data.verified;
    const onChain     = normalize(data.on_chain_digest);
    const serverLocal = normalize(data.local_digest);
    const timestamp   = tsToHuman(data.timestamp);
    const etherscan   = data.etherscan_url;
    const recordIdx   = data.record_index;

    const verdictClass = verified ? "pass" : "fail";
    const verdictLabel = verified ? "✓ PASS — digest matches on-chain record" : "✗ FAIL — digest does not match on-chain record";

    // Compare local browser hash with on-chain hash (only when text was provided)
    let localSection = "";
    if (localHash !== null) {
      const localMatch = localHash === onChain;
      const matchLabel = localMatch
        ? `<span class="match">✓ matches on-chain digest</span>`
        : `<span class="mismatch">✗ does not match on-chain digest</span>`;
      localSection = `
        <div class="local-section">
          <strong>Locally computed keccak256 (browser, no server)</strong>
          <code>${escHtml(localHash)}</code>
          <div style="margin-top:4px;">${matchLabel}</div>
        </div>`;
    }

    resultEl.innerHTML = `
      <div class="verdict ${verdictClass}">${verdictLabel}</div>
      <table>
        <tr><td>Conversation ID</td><td>${escHtml(data.conversation_id)}</td></tr>
        <tr><td>Record index</td><td>${escHtml(String(recordIdx))}</td></tr>
        <tr><td>On-chain digest</td><td><code>${escHtml(onChain)}</code></td></tr>
        <tr><td>Server local digest</td><td><code>${escHtml(serverLocal)}</code></td></tr>
        <tr><td>Block timestamp</td><td>${escHtml(timestamp)}</td></tr>
        <tr><td>Etherscan</td><td><a href="${escHtml(etherscan)}" target="_blank" rel="noopener">${escHtml(etherscan)}</a></td></tr>
      </table>
      ${localSection}`;
  }
