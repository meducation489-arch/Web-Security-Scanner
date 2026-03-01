async function scan() {
  const url = document.getElementById("url").value.trim();
  const cards = document.getElementById("cards");
  const report = document.getElementById("report");
  const inputBox = document.getElementById("inputBox");

  if (!url) {
    alert("❌ Enter a valid URL");
    return;
  }

  cards.innerHTML = "";
  inputBox.style.display = "none";
  report.classList.remove("hidden");

  const tools = [
    { name: "Port Scan", ep: "ports" },
    { name: "Headers Scan", ep: "headers" },
    { name: "SSL Scan", ep: "ssl" },
    { name: "Cookie Scan", ep: "cookies" },
    { name: "SQL Injection Scan", ep: "sql" },
    { name: "XSS Scan", ep: "xss" },
    { name: "Directory Scan", ep: "dir" },
    { name: "HTTP Methods Scan", ep: "methods" }
  ];

  for (let tool of tools) {
    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML = `<h3>${tool.name}</h3><p>⏳ Scanning...</p>`;
    cards.appendChild(card);

    try {
      const res = await fetch(`http://127.0.0.1:5000/scan/${tool.ep}?url=${encodeURIComponent(url)}`
      );

      if (!res.ok) throw new Error("Backend error");

      const data = await res.json();
      card.innerHTML = `<h3>${tool.name}</h3>${renderTool(tool.ep, data)}`;

    } catch (err) {
      card.innerHTML = `
        <h3>${tool.name}</h3>
        <p class="bad">❌ Scan failed or endpoint not available</p>
      `;
      console.error(tool.name, err);
    }
  }
}

function resetScan() {
  document.getElementById("cards").innerHTML = "";
  document.getElementById("report").classList.add("hidden");
  document.getElementById("inputBox").style.display = "block";
  document.getElementById("url").value = "";
}

/* ================= RENDER FUNCTIONS ================= */

function renderTool(type, data) {
  switch (type) {
    case "ports": return renderPorts(data);
    case "headers": return renderHeaders(data);
    case "ssl": return renderSSL(data);
    case "dir": return renderDir(data);
    case "methods": return renderMethods(data);
    case "sql": return renderSQL(data);
    case "xss": return renderXSS(data);
    default:
      return `<pre>${JSON.stringify(data, null, 2)}</pre>`;
  }
}

/* -------- PORT SCAN -------- */
function renderPorts(data) {
  if (!data.open_ports || data.open_ports.length === 0)
    return "<p>✅ No risky open ports</p>";

  return `
    <table>
      <tr><th>Port</th><th>Risk</th></tr>
      ${data.open_ports.map(p => `
        <tr>
          <td>${p}</td>
          <td class="${p === 21 || p === 3306 ? "high" : "medium"}">
            ${p === 21 || p === 3306 ? "High" : "Medium"}
          </td>
        </tr>
      `).join("")}
    </table>
  `;
}

/* -------- HEADERS -------- */
function renderHeaders(data) {
  if (!data.security_headers) return "<p>No header info</p>";

  return `
    <table>
      <tr><th>Header</th><th>Status</th></tr>
      ${Object.entries(data.security_headers).map(
        ([k, v]) => `
          <tr>
            <td>${k}</td>
            <td class="${v === "Present" ? "good" : "bad"}">${v}</td>
          </tr>
        `
      ).join("")}
    </table>
  `;
}

/* -------- SSL -------- */
function renderSSL(data) {
  if (!data.ssl_details) return "<p>No SSL data</p>";

  return `
    <p><b>Issuer:</b> ${data.ssl_details.Issuer?.organizationName || "Unknown"}</p>
    <p><b>Valid Until:</b> ${data.ssl_details["Valid Until"]}</p>
    <p><b>Risk:</b> <span class="low">${data.ssl_details.Risk}</span></p>
  `;
}

/* -------- DIRECTORY -------- */
function renderDir(data) {
  if (!data.directories_found || data.directories_found.length === 0)
    return "<p>✅ No sensitive directories found</p>";

  return `<ul>${data.directories_found.map(d => `<li>${d}</li>`).join("")}</ul>`;
}

/* -------- HTTP METHODS -------- */
function renderMethods(data) {
  if (!data.allowed_methods) return "<p>No methods data</p>";

  return `<p><b>Allowed:</b> ${data.allowed_methods.join(", ")}</p>`;
}

/* -------- SQL INJECTION -------- */
function renderSQL(data) {
  return data.vulnerable
    ? `<p class="high">❌ SQL Injection Possible</p>`
    : `<p class="good">✅ No SQL Injection Found</p>`;
}

/* -------- XSS -------- */
function renderXSS(data) {
  return data.vulnerable
    ? `<p class="high">❌ XSS Vulnerability Detected</p>`
    : `<p class="good">✅ No XSS Found</p>`;
}

/* -------- COOKIE SCAN -------- */
function displayCookies(data) {
    const container = document.getElementById("cards");
    container.innerHTML = "";

    let table = `
        <table style="width:100%; border-collapse: collapse;">
            <tr>
                <th>Name</th>
                <th>Secure</th>
                <th>HttpOnly</th>
                <th>Risk</th>
            </tr>
    `;

    data.cookies.forEach(cookie => {
        table += `
            <tr>
                <td>${cookie.name}</td>
                <td>${cookie.secure ? "✅" : "❌"}</td>
                <td>${cookie.httponly ? "✅" : "❌"}</td>
                <td style="color:${cookie.risk === "High" ? "red" : "green"}">
                    ${cookie.risk}
                </td>
            </tr>
        `;
    });

    table += "</table>";
    container.innerHTML = table;
}