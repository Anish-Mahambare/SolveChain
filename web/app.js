const form = document.getElementById("solve-form");
const submitButton = document.getElementById("submit-button");
const statusLine = document.getElementById("status-line");
const emptyState = document.getElementById("empty-state");
const resultView = document.getElementById("result-view");
const summaryGrid = document.getElementById("summary-grid");
const logOutput = document.getElementById("log-output");
const stepsList = document.getElementById("steps-list");
const rawResult = document.getElementById("raw-result");
const historyList = document.getElementById("history-list");

const runHistory = [];

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function truncate(text, maxLength = 180) {
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength - 1)}…`;
}

function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.style.color = isError ? "var(--signal)" : "var(--muted)";
}

function renderSummary(summary) {
  const cards = [
    ["Status", summary.status ?? "unknown", `status-${summary.status ?? "unknown"}`],
    ["Steps Taken", String(summary.steps_taken ?? 0), ""],
    ["Flag Found", summary.flag_found ? "Yes" : "No", ""],
    ["Final Flag", summary.flag ?? "No flag found.", "flag"],
  ];

  if (summary.reason) {
    cards.push(["Reason", summary.reason, ""]);
  }

  summaryGrid.innerHTML = cards
    .map(([label, value, extraClass]) => {
      return `
        <dl class="summary-card ${escapeHtml(extraClass)}">
          <dt>${escapeHtml(label)}</dt>
          <dd>${escapeHtml(value)}</dd>
        </dl>
      `;
    })
    .join("");
}

function renderSteps(steps) {
  if (!steps.length) {
    stepsList.innerHTML = `<div class="history-empty">No tool steps were recorded.</div>`;
    return;
  }

  stepsList.innerHTML = steps
    .map((step) => {
      const failedAttempts = step.failed_attempts?.length
        ? `
          <div class="mini-label">Failed Attempts</div>
          <pre class="mini-block">${escapeHtml(JSON.stringify(step.failed_attempts, null, 2))}</pre>
        `
        : "";

      return `
        <article class="step-card">
          <div class="step-head">
            <div class="step-meta">
              <span class="step-index">Step ${escapeHtml(step.index)}</span>
              <span class="step-tool">${escapeHtml(step.tool)}</span>
            </div>
            <span class="step-confidence">Confidence ${escapeHtml(step.confidence ?? "n/a")}</span>
          </div>
          <div class="step-body">
            <p>${escapeHtml(step.reason || "No recorded rationale.")}</p>
            <div class="mini-label">Parameters</div>
            <pre class="mini-block">${escapeHtml(JSON.stringify(step.params ?? {}, null, 2))}</pre>
            ${failedAttempts}
            <div class="mini-label">Result</div>
            <pre class="mini-block">${escapeHtml(step.rendered_output || "")}</pre>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderResult(run) {
  emptyState.classList.add("hidden");
  resultView.classList.remove("hidden");

  renderSummary(run.summary);
  logOutput.textContent = (run.logs && run.logs.length ? run.logs.join("\n") : "No logs captured.");
  renderSteps(run.steps || []);
  rawResult.textContent = JSON.stringify(run.raw_result ?? {}, null, 2);
}

function renderHistory() {
  if (!runHistory.length) {
    historyList.innerHTML = `<div class="history-empty">Past runs will appear here.</div>`;
    return;
  }

  historyList.innerHTML = runHistory
    .map((run, index) => {
      const label = run.summary.flag || run.summary.status || "run";
      return `
        <article class="history-card">
          <button type="button" data-history-index="${index}">
            <p class="history-title">${escapeHtml(label)}</p>
            <p class="history-meta">${escapeHtml(run.file_path || "No file")} • ${escapeHtml(String(run.summary.steps_taken ?? 0))} step(s)</p>
            <p class="history-preview">${escapeHtml(truncate(run.description || "", 150))}</p>
          </button>
        </article>
      `;
    })
    .join("");
}

historyList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-history-index]");
  if (!button) {
    return;
  }

  const index = Number(button.getAttribute("data-history-index"));
  const selected = runHistory[index];
  if (selected) {
    renderResult(selected);
    setStatus("Loaded a previous run from history.");
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const formData = new FormData(form);
  const payload = {
    description: String(formData.get("description") || "").trim(),
    file_path: String(formData.get("file_path") || "").trim(),
    max_steps: Number(formData.get("max_steps") || 10),
  };

  submitButton.disabled = true;
  setStatus("Solver running. Capturing logs and tool output...");

  try {
    const response = await fetch("/api/solve", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Request failed.");
    }

    runHistory.unshift(data);
    renderResult(data);
    renderHistory();
    setStatus(`Run complete with status: ${data.summary.status}.`);
  } catch (error) {
    setStatus(error.message || "Solver request failed.", true);
  } finally {
    submitButton.disabled = false;
  }
});

renderHistory();
