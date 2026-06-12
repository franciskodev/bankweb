const appState = {
  user: null,
  dashboard: { accounts: [], transactions: [] },
  users: [],
  adminAccounts: [],
};

const money = new Intl.NumberFormat("ru-RU", {
  style: "currency",
  currency: "RUB",
  maximumFractionDigits: 2,
});

const authScreen = document.querySelector("#auth-screen");
const appShell = document.querySelector("#app-shell");
const loginForm = document.querySelector("#login-form");
const loginMessage = document.querySelector("#login-message");
const registerForm = document.querySelector("#register-form");
const registerMessage = document.querySelector("#register-message");
const transferForm = document.querySelector("#transfer-form");
const transferMessage = document.querySelector("#transfer-message");
const ownAccountForm = document.querySelector("#own-account-form");
const userForm = document.querySelector("#user-form");
const accountAdjustForm = document.querySelector("#account-adjust-form");
const accountCreateForm = document.querySelector("#account-create-form");

function formatMoney(kopeks) {
  return money.format((kopeks || 0) / 100);
}

function formatDate(value) {
  return new Intl.DateTimeFormat("ru-RU", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  })[char]);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || "Ошибка запроса.");
  return payload;
}

function showOnly(screen) {
  authScreen.classList.toggle("hidden", screen !== "login");
  appShell.classList.toggle("hidden", screen !== "app");
}

function isAdmin() {
  return appState.user?.role === "admin";
}

function showAuthenticated(user) {
  appState.user = user;
  showOnly("app");
  document.querySelector("#current-name").textContent = user.name;
  document.querySelector("#current-email").textContent = user.email;
  document.querySelector("#current-role").textContent = `${user.role} · ${user.status}`;
  document.querySelector("#hello-title").textContent = `Добро пожаловать, ${user.name}`;
  document.querySelector("#user-avatar").textContent = user.name.slice(0, 1).toUpperCase();
  document.querySelector("#status-text").textContent = `${user.role} · ${user.status}`;
  document.querySelectorAll(".admin-only").forEach((item) => {
    item.classList.toggle("hidden", !isAdmin());
  });
}

function switchView(viewId) {
  if ((viewId === "admin" || viewId === "admin-accounts") && !isAdmin()) return;
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view.id === viewId);
  });
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.view === viewId);
  });
  if (viewId === "admin") loadUsers();
  if (viewId === "admin-accounts") loadAdminAccounts();
}

function renderDashboard() {
  const { accounts, transactions } = appState.dashboard;
  const total = accounts.reduce((sum, account) => sum + account.balance, 0);
  const spend = transactions
    .filter((transaction) => transaction.amount < 0)
    .reduce((sum, transaction) => sum + Math.abs(transaction.amount), 0);

  document.querySelector("#total-balance").textContent = formatMoney(total);
  document.querySelector("#month-spend").textContent = formatMoney(spend);
  document.querySelector("#accounts-count").textContent = `${accounts.length} счетов`;
  document.querySelector("#overview-accounts").innerHTML = accounts.map(renderAccountRow).join("");
  document.querySelector("#accounts-grid").innerHTML = accounts.map(renderAccountCard).join("");
  document.querySelector("#activity-list").innerHTML = transactions.map(renderTransactionRow).join("");
  document.querySelector("#from-account").innerHTML = accounts
    .filter((account) => account.status === "active")
    .map((account) => `<option value="${account.id}">${escapeHtml(account.name)} · ${formatMoney(account.balance)}</option>`)
    .join("");

  const createAccountButton = document.querySelector("#create-own-account");
  const accountLimit = document.querySelector("#own-account-limit");
  const accountCount = accounts.length;
  createAccountButton.disabled = accountCount >= 3;
  accountLimit.textContent = accountCount >= 3
    ? "Достигнут лимит: 3 счета"
    : `Можно создать еще ${3 - accountCount}`;
}

function renderAccountRow(account) {
  return `
    <article class="account-row">
      <span class="row-icon">₽</span>
      <div>
        <p class="row-title">${escapeHtml(account.name)}</p>
        <p class="row-subtitle">${escapeHtml(account.number)} · ${escapeHtml(account.status)}</p>
      </div>
      <strong class="amount">${formatMoney(account.balance)}</strong>
    </article>
  `;
}

function renderAccountCard(account) {
  return `
    <article class="account-card">
      <div>
        <p class="row-title">${escapeHtml(account.name)}</p>
        <p class="account-number">${escapeHtml(account.number)} · ${escapeHtml(account.status)}</p>
      </div>
      <strong class="account-balance">${formatMoney(account.balance)}</strong>
      <button class="ghost-button" data-view="transfer" type="button">Перевести</button>
    </article>
  `;
}

function renderTransactionRow(transaction) {
  const isPositive = transaction.amount > 0;
  return `
    <article class="activity-row">
      <span class="row-icon">${isPositive ? "↓" : "↑"}</span>
      <div>
        <p class="row-title">${escapeHtml(transaction.title)}</p>
        <p class="row-subtitle">${escapeHtml(transaction.note)} · ${escapeHtml(transaction.status)} · ${formatDate(transaction.createdAt)}</p>
      </div>
      <strong class="amount ${isPositive ? "positive" : "negative"}">${isPositive ? "+" : ""}${formatMoney(transaction.amount)}</strong>
    </article>
  `;
}

function renderUsers() {
  document.querySelector("#users-table").innerHTML = appState.users.map((user) => `
    <article class="user-row">
      <div>
        <p class="row-title">${escapeHtml(user.name)} ${user.isSystem ? '<span class="system-badge">system</span>' : ""}</p>
        <p class="row-subtitle">${escapeHtml(user.username || "без логина")} · ${escapeHtml(user.email)}</p>
      </div>
      <select data-user-role="${user.id}" ${user.isSystem ? "disabled" : ""}>
        <option value="client" ${user.role === "client" ? "selected" : ""}>client</option>
        <option value="manager" ${user.role === "manager" ? "selected" : ""}>manager</option>
        <option value="admin" ${user.role === "admin" ? "selected" : ""}>admin</option>
      </select>
      <select data-user-status="${user.id}" ${user.isSystem ? "disabled" : ""}>
        <option value="active" ${user.status === "active" ? "selected" : ""}>active</option>
        <option value="blocked" ${user.status === "blocked" ? "selected" : ""}>blocked</option>
      </select>
      <div class="user-actions">
        <button class="mini-button" data-save-user="${user.id}" type="button">Сохранить</button>
        ${user.isSystem ? "" : `<button class="mini-button danger" data-delete-user="${user.id}" type="button">Удалить</button>`}
      </div>
    </article>
  `).join("");
}

function renderAdminAccounts() {
  document.querySelector("#account-user").innerHTML = appState.users.map((user) => `
    <option value="${user.id}">${escapeHtml(user.email)} · ${escapeHtml(user.name)}</option>
  `).join("");

  document.querySelector("#adjust-account").innerHTML = appState.adminAccounts.map((account) => `
    <option value="${account.id}">${escapeHtml(account.ownerEmail)} · ${escapeHtml(account.name)} · ${formatMoney(account.balance)}</option>
  `).join("");

  document.querySelector("#admin-accounts-table").innerHTML = appState.adminAccounts.map((account) => `
    <article class="user-row account-admin-row">
      <div>
        <p class="row-title">${escapeHtml(account.ownerName)}</p>
        <p class="row-subtitle">${escapeHtml(account.ownerEmail)}</p>
      </div>
      <div>
        <p class="row-title">${escapeHtml(account.name)}</p>
        <p class="row-subtitle">${escapeHtml(account.number)}</p>
      </div>
      <strong class="amount">${formatMoney(account.balance)}</strong>
      <span class="row-subtitle">${escapeHtml(account.status)}</span>
    </article>
  `).join("");
}

async function loadDashboard() {
  appState.dashboard = await api("/api/me/dashboard");
  renderDashboard();
}

async function loadUsers() {
  if (!isAdmin()) return;
  const payload = await api("/api/admin/users");
  appState.users = payload.users;
  renderUsers();
}

async function loadAdminAccounts() {
  if (!isAdmin()) return;
  if (!appState.users.length) {
    await loadUsers();
  }
  const payload = await api("/api/admin/accounts");
  appState.adminAccounts = payload.accounts;
  renderAdminAccounts();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginMessage.textContent = "";
  try {
    const payload = await api("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: document.querySelector("#login-email").value,
        password: document.querySelector("#login-password").value,
      }),
    });
    showAuthenticated(payload.user);
    await loadDashboard();
  } catch (error) {
    loginMessage.textContent = error.message;
  }
});

document.querySelector("#show-register").addEventListener("click", () => {
  loginForm.classList.add("hidden");
  document.querySelector("#show-register").classList.add("hidden");
  registerForm.classList.remove("hidden");
  loginMessage.textContent = "";
});

document.querySelector("#hide-register").addEventListener("click", () => {
  registerForm.classList.add("hidden");
  loginForm.classList.remove("hidden");
  document.querySelector("#show-register").classList.remove("hidden");
  registerMessage.textContent = "";
});

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  registerMessage.textContent = "";
  try {
    const payload = await api("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        name: document.querySelector("#register-name").value,
        username: document.querySelector("#register-username").value,
        email: document.querySelector("#register-email").value,
        password: document.querySelector("#register-password").value,
      }),
    });
    registerForm.reset();
    showAuthenticated(payload.user);
    await loadDashboard();
  } catch (error) {
    registerMessage.textContent = error.message;
  }
});

transferForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  transferMessage.textContent = "";
  try {
    const payload = await api("/api/me/transfer", {
      method: "POST",
      body: JSON.stringify({
        accountId: document.querySelector("#from-account").value,
        recipient: document.querySelector("#recipient").value,
        amount: document.querySelector("#amount").value,
        note: document.querySelector("#note").value,
      }),
    });
    appState.dashboard = payload.dashboard;
    transferForm.reset();
    transferMessage.textContent = "Перевод выполнен.";
    renderDashboard();
    switchView("overview");
  } catch (error) {
    transferMessage.textContent = error.message;
  }
});

ownAccountForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const payload = await api("/api/me/accounts", {
      method: "POST",
      body: JSON.stringify({
        name: document.querySelector("#own-account-name").value,
      }),
    });
    appState.dashboard = payload.dashboard;
    ownAccountForm.reset();
    renderDashboard();
  } catch (error) {
    alert(error.message);
  }
});

userForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await api("/api/admin/users", {
    method: "POST",
    body: JSON.stringify({
      name: document.querySelector("#new-name").value,
      username: document.querySelector("#new-username").value,
      email: document.querySelector("#new-email").value,
      password: document.querySelector("#new-password").value,
      role: document.querySelector("#new-role").value,
      status: "active",
      initialBalance: document.querySelector("#new-balance").value || "0",
    }),
  });
  userForm.reset();
  await loadUsers();
  await loadAdminAccounts();
});

accountAdjustForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await api("/api/admin/accounts/adjust", {
    method: "POST",
    body: JSON.stringify({
      accountId: document.querySelector("#adjust-account").value,
      direction: document.querySelector("#adjust-direction").value,
      amount: document.querySelector("#adjust-amount").value,
      note: document.querySelector("#adjust-note").value,
    }),
  });
  accountAdjustForm.reset();
  await loadAdminAccounts();
  await loadDashboard();
});

accountCreateForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await api("/api/admin/accounts", {
    method: "POST",
    body: JSON.stringify({
      userId: document.querySelector("#account-user").value,
      name: document.querySelector("#account-name").value,
      initialBalance: document.querySelector("#account-initial-balance").value || "0",
    }),
  });
  accountCreateForm.reset();
  await loadAdminAccounts();
});

document.addEventListener("click", async (event) => {
  const viewControl = event.target.closest("[data-view]");
  if (viewControl) {
    switchView(viewControl.dataset.view);
    return;
  }

  const saveButton = event.target.closest("[data-save-user]");
  if (saveButton) {
    const id = saveButton.dataset.saveUser;
    const user = appState.users.find((item) => String(item.id) === String(id));
    await api(`/api/admin/users/${id}`, {
      method: "PUT",
      body: JSON.stringify({
        name: user.name,
        role: document.querySelector(`[data-user-role="${id}"]`).value,
        status: document.querySelector(`[data-user-status="${id}"]`).value,
      }),
    });
    await loadUsers();
    return;
  }

  const deleteButton = event.target.closest("[data-delete-user]");
  if (deleteButton && confirm("Удалить пользователя и его счета?")) {
    await api(`/api/admin/users/${deleteButton.dataset.deleteUser}`, { method: "DELETE" });
    await loadUsers();
    await loadAdminAccounts();
  }
});

document.querySelector("#logout-button").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST", body: "{}" }).catch(() => {});
  appState.user = null;
  showOnly("login");
});

(async function boot() {
  try {
    const session = await api("/api/session");
    if (!session.user) {
      showOnly("login");
      return;
    }
    showAuthenticated(session.user);
    await loadDashboard();
  } catch (error) {
    loginMessage.textContent = error.message;
    showOnly("login");
  }
})();
