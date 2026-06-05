const state = {
  csrfToken: null,
  sites: [],
  refreshTimer: null,
  autoRefreshMs: 30000,
};

const els = {
  authView: document.querySelector("#authView"),
  dashboardView: document.querySelector("#dashboardView"),
  loginForm: document.querySelector("#loginForm"),
  loginError: document.querySelector("#loginError"),
  username: document.querySelector("#username"),
  password: document.querySelector("#password"),
  logoutButton: document.querySelector("#logoutButton"),
  passwordButton: document.querySelector("#passwordButton"),
  addSiteButton: document.querySelector("#addSiteButton"),
  refreshAllButton: document.querySelector("#refreshAllButton"),
  refreshStatus: document.querySelector("#refreshStatus"),
  checkPulse: document.querySelector("#checkPulse"),
  tableBody: document.querySelector("#sitesTableBody"),
  emptyState: document.querySelector("#emptyState"),
  totalCount: document.querySelector("#totalCount"),
  availableCount: document.querySelector("#availableCount"),
  downCount: document.querySelector("#downCount"),
  sslWarnCount: document.querySelector("#sslWarnCount"),
  sslExpiredCount: document.querySelector("#sslExpiredCount"),
  siteModal: document.querySelector("#siteModal"),
  siteModalTitle: document.querySelector("#siteModalTitle"),
  siteForm: document.querySelector("#siteForm"),
  siteFormError: document.querySelector("#siteFormError"),
  siteId: document.querySelector("#siteId"),
  siteName: document.querySelector("#siteName"),
  siteUrl: document.querySelector("#siteUrl"),
  domainExpiresAt: document.querySelector("#domainExpiresAt"),
  passwordModal: document.querySelector("#passwordModal"),
  passwordForm: document.querySelector("#passwordForm"),
  passwordFormError: document.querySelector("#passwordFormError"),
  currentPassword: document.querySelector("#currentPassword"),
  newPassword: document.querySelector("#newPassword"),
};

async function api(path, options = {}) {
  const method = options.method || "GET";
  const headers = new Headers(options.headers || {});
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (method !== "GET" && state.csrfToken) {
    headers.set("X-CSRF-Token", state.csrfToken);
  }

  const response = await fetch(path, {
    ...options,
    method,
    headers,
    credentials: "same-origin",
  });

  const contentType = response.headers.get("Content-Type") || "";
  const data = contentType.includes("application/json") ? await response.json() : {};

  if (response.status === 401) {
    showAuth();
  }
  if (!response.ok) {
    throw new Error(data.error || "Ошибка запроса");
  }
  return data;
}

function showAuth() {
  stopAutoRefresh();
  state.csrfToken = null;
  state.sites = [];
  els.dashboardView.classList.add("is-hidden");
  els.authView.classList.remove("is-hidden");
  els.password.value = "";
  window.setTimeout(() => els.username.focus(), 0);
}

function showDashboard() {
  els.authView.classList.add("is-hidden");
  els.dashboardView.classList.remove("is-hidden");
  startAutoRefresh();
}

function startAutoRefresh() {
  stopAutoRefresh();
  state.refreshTimer = window.setInterval(() => loadSites(false), state.autoRefreshMs);
}

function stopAutoRefresh() {
  if (state.refreshTimer) {
    window.clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
}

function formatDateTime(value) {
  if (!value) {
    return "—";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "—";
  }
  return new Intl.DateTimeFormat("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatDate(value) {
  if (!value) {
    return "—";
  }
  const date = value.includes("T") ? new Date(value) : new Date(`${value}T00:00:00`);
  if (Number.isNaN(date.getTime())) {
    return "—";
  }
  return new Intl.DateTimeFormat("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  }).format(date);
}

function availabilityBadge(site) {
  if (site.availability_status === "available") {
    return badge("Доступен", "ok");
  }
  if (site.availability_status === "unavailable") {
    return `${badge("Недоступен", "danger")}${site.last_error ? `<span class="row-error">${escapeHtml(site.last_error)}</span>` : ""}`;
  }
  return badge("Не проверено", "unknown");
}

function sslBadge(status) {
  const labels = {
    valid: ["Действителен", "ok"],
    expiring: ["Истекает скоро", "warn"],
    expired: ["Просрочен", "danger"],
    missing: ["SSL отсутствует", "unknown"],
    unknown: ["Не проверено", "unknown"],
  };
  const [label, tone] = labels[status] || labels.unknown;
  return badge(label, tone);
}

function badge(label, tone) {
  return `<span class="badge badge-${tone}">${label}</span>`;
}

function daysClass(days) {
  if (days === null || days === undefined || days === "") {
    return "muted";
  }
  if (Number(days) < 0) {
    return "days-danger";
  }
  if (Number(days) < 14) {
    return "days-warn";
  }
  return "days-ok";
}

function formatDays(days) {
  if (days === null || days === undefined || days === "") {
    return "—";
  }
  return String(days);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderSites() {
  const rows = state.sites.map((site) => {
    const sslDaysClass = daysClass(site.ssl_days_remaining);
    const domainDaysClass = daysClass(site.domain_days_remaining);
    const responseTime = site.response_time_ms ? `<span class="muted">${site.response_time_ms} мс</span>` : "";
    return `
      <tr>
        <td data-label="Название"><div class="site-name">${escapeHtml(site.name)}</div></td>
        <td data-label="URL"><a class="site-url" href="${escapeHtml(site.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(site.url)}</a></td>
        <td data-label="Доступность">${availabilityBadge(site)}</td>
        <td data-label="HTTP">${site.http_status ?? "—"} ${responseTime}</td>
        <td data-label="Последняя проверка">${formatDateTime(site.last_checked_at)}</td>
        <td data-label="SSL">${sslBadge(site.ssl_status)}</td>
        <td data-label="Окончание SSL">${formatDate(site.ssl_expires_at)}</td>
        <td data-label="Дней SSL"><span class="${sslDaysClass}">${formatDays(site.ssl_days_remaining)}</span></td>
        <td data-label="Хостинг/домен">${formatDate(site.domain_expires_at)}</td>
        <td data-label="Дней"><span class="${domainDaysClass}">${formatDays(site.domain_days_remaining)}</span></td>
        <td data-label="Действия">
          <div class="actions-cell">
            <button class="button button-secondary table-button" data-action="check" data-id="${site.id}" type="button">Проверить сейчас</button>
            <button class="button button-ghost table-button" data-action="edit" data-id="${site.id}" type="button">Редактировать</button>
            <button class="button button-danger table-button" data-action="delete" data-id="${site.id}" type="button">Удалить</button>
          </div>
        </td>
      </tr>
    `;
  });

  els.tableBody.innerHTML = rows.join("");
  els.emptyState.classList.toggle("is-hidden", state.sites.length > 0);
  renderSummary();
}

function renderSummary() {
  const total = state.sites.length;
  const available = state.sites.filter((site) => site.availability_status === "available").length;
  const down = state.sites.filter((site) => site.availability_status === "unavailable").length;
  const sslWarn = state.sites.filter((site) => site.ssl_status === "expiring").length;
  const sslExpired = state.sites.filter((site) => site.ssl_status === "expired").length;

  els.totalCount.textContent = total;
  els.availableCount.textContent = available;
  els.downCount.textContent = down;
  els.sslWarnCount.textContent = sslWarn;
  els.sslExpiredCount.textContent = sslExpired;
}

function setRefreshStatus(text, checking = false) {
  els.refreshStatus.textContent = text;
  els.checkPulse.classList.toggle("is-active", checking);
}

async function loadSites(showStatus = true) {
  if (showStatus) {
    setRefreshStatus("Обновление", true);
  }
  try {
    const data = await api("/api/sites");
    state.sites = data.sites;
    renderSites();
    setRefreshStatus(data.checking ? "Проверка выполняется" : `Обновлено ${formatDateTime(data.server_time)}`, data.checking);
  } catch (error) {
    if (showStatus) {
      setRefreshStatus(error.message, false);
    }
  }
}

function openSiteModal(site = null) {
  els.siteFormError.textContent = "";
  els.siteId.value = site?.id || "";
  els.siteName.value = site?.name || "";
  els.siteUrl.value = site?.url || "";
  els.domainExpiresAt.value = site?.domain_expires_at || "";
  els.siteModalTitle.textContent = site ? "Редактировать сайт" : "Добавить сайт";
  els.siteModal.showModal();
}

function openPasswordModal() {
  els.passwordFormError.textContent = "";
  els.currentPassword.value = "";
  els.newPassword.value = "";
  els.passwordModal.showModal();
}

function closeModals() {
  for (const modal of document.querySelectorAll("dialog[open]")) {
    modal.close();
  }
}

async function handleLogin(event) {
  event.preventDefault();
  els.loginError.textContent = "";
  const submitButton = els.loginForm.querySelector("button[type='submit']");
  submitButton.disabled = true;
  try {
    const data = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: els.username.value,
        password: els.password.value,
      }),
    });
    state.csrfToken = data.csrf_token;
    showDashboard();
    await loadSites();
  } catch (error) {
    els.loginError.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
}

async function handleLogout() {
  try {
    await api("/api/logout", { method: "POST" });
  } finally {
    showAuth();
  }
}

async function handleSiteSubmit(event) {
  event.preventDefault();
  els.siteFormError.textContent = "";
  const id = els.siteId.value;
  const payload = {
    name: els.siteName.value.trim(),
    url: els.siteUrl.value.trim(),
    domain_expires_at: els.domainExpiresAt.value || null,
  };
  const submitButton = els.siteForm.querySelector("button[type='submit']");
  submitButton.disabled = true;
  try {
    await api(id ? `/api/sites/${id}` : "/api/sites", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    closeModals();
    await loadSites();
  } catch (error) {
    els.siteFormError.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
}

async function handlePasswordSubmit(event) {
  event.preventDefault();
  els.passwordFormError.textContent = "";
  const submitButton = els.passwordForm.querySelector("button[type='submit']");
  submitButton.disabled = true;
  try {
    await api("/api/change-password", {
      method: "POST",
      body: JSON.stringify({
        current_password: els.currentPassword.value,
        new_password: els.newPassword.value,
      }),
    });
    closeModals();
  } catch (error) {
    els.passwordFormError.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
}

async function handleRefreshAll() {
  els.refreshAllButton.disabled = true;
  setRefreshStatus("Запуск проверки", true);
  try {
    await api("/api/sites/check-all", { method: "POST" });
    window.setTimeout(() => loadSites(false), 1200);
  } catch (error) {
    setRefreshStatus(error.message, false);
  } finally {
    window.setTimeout(() => {
      els.refreshAllButton.disabled = false;
    }, 1200);
  }
}

async function handleTableClick(event) {
  const button = event.target.closest("button[data-action]");
  if (!button) {
    return;
  }
  const siteId = Number(button.dataset.id);
  const site = state.sites.find((item) => item.id === siteId);
  if (!site) {
    return;
  }

  if (button.dataset.action === "edit") {
    openSiteModal(site);
    return;
  }

  if (button.dataset.action === "delete") {
    const confirmed = window.confirm(`Удалить сайт "${site.name}"?`);
    if (!confirmed) {
      return;
    }
    button.disabled = true;
    try {
      await api(`/api/sites/${siteId}`, { method: "DELETE" });
      await loadSites();
    } catch (error) {
      setRefreshStatus(error.message, false);
    }
    return;
  }

  if (button.dataset.action === "check") {
    button.disabled = true;
    button.textContent = "Проверка";
    try {
      const data = await api(`/api/sites/${siteId}/check`, { method: "POST" });
      state.sites = state.sites.map((item) => (item.id === siteId ? data.site : item));
      renderSites();
      setRefreshStatus(`Проверено ${formatDateTime(data.site.last_checked_at)}`, false);
    } catch (error) {
      setRefreshStatus(error.message, false);
    }
  }
}

async function bootstrap() {
  try {
    const data = await api("/api/me");
    state.csrfToken = data.csrf_token;
    showDashboard();
    await loadSites();
  } catch {
    showAuth();
  }
}

els.loginForm.addEventListener("submit", handleLogin);
els.logoutButton.addEventListener("click", handleLogout);
els.addSiteButton.addEventListener("click", () => openSiteModal());
els.passwordButton.addEventListener("click", openPasswordModal);
els.refreshAllButton.addEventListener("click", handleRefreshAll);
els.siteForm.addEventListener("submit", handleSiteSubmit);
els.passwordForm.addEventListener("submit", handlePasswordSubmit);
els.tableBody.addEventListener("click", handleTableClick);

document.addEventListener("click", (event) => {
  if (event.target.matches("[data-close-modal]")) {
    closeModals();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeModals();
  }
});

bootstrap();
