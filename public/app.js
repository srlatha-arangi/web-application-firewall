
const logsElement = document.getElementById("logs");
const resultElement = document.getElementById("result");

async function refreshLogs() {
  const response = await fetch("/api/logs");
  const logs = await response.json();

  logsElement.replaceChildren();

  for (const log of logs) {
    const row = document.createElement("tr");

    for (const value of [
      log.time,
      log.url,
      log.status,
      log.reason
    ]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    }

    row.children[2].className =
      log.status === "BLOCKED" ? "blocked" : "allowed";

    logsElement.appendChild(row);
  }
}

document.getElementById("refresh").addEventListener(
  "click",
  refreshLogs
);

document.getElementById("test").addEventListener(
  "click",
  async () => {
    const requestPath =
      document.getElementById("testPath").value;

    if (
      !requestPath.startsWith("/") ||
      requestPath.startsWith("//") ||
      requestPath.includes("#")
    ) {
      resultElement.textContent =
        "Enter a local path beginning with /";
      return;
    }

    try {
      const response = await fetch(requestPath);
      const message = await response.text();

      resultElement.textContent =
        `HTTP ${response.status}: ${message.slice(0, 180)}`;

      await refreshLogs();
    } catch {
      resultElement.textContent = "Request failed.";
    }
  }
);

refreshLogs();
