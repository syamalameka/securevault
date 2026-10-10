/**
 * SecureVault Main Dashboard Logic
 */

let currentUser = null;
let currentDocuments = [];

document.addEventListener("DOMContentLoaded", async () => {
  setupEventListeners();
  await initApp();
});

async function initApp() {
  // Check if we have an active user or default to Manager Bob for demo
  currentUser = API.getCurrentUser();
  if (!currentUser) {
    try {
      const data = await API.demoLogin("MANAGER");
      currentUser = data.user;
    } catch (e) {
      console.error("Init login error:", e);
    }
  }

  updateUserBadge();
  await refreshDashboard();
}

function updateUserBadge() {
  if (!currentUser) return;
  const avatar = document.getElementById("user-avatar");
  const displayName = document.getElementById("user-display-name");
  const displayRole = document.getElementById("user-display-role");

  avatar.textContent = currentUser.full_name ? currentUser.full_name[0] : "U";
  displayName.textContent = currentUser.full_name || currentUser.username;
  displayRole.textContent = currentUser.role;

  // Highlight active role switcher button
  document.querySelectorAll(".role-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.role === currentUser.role);
  });
}

async function refreshDashboard() {
  await Promise.all([
    loadDocuments(),
    loadAuditStats(),
    loadUsersDirectory()
  ]);
}

async function loadDocuments() {
  const query = document.getElementById("doc-search-input").value.trim();
  const category = document.getElementById("category-filter").value;
  const tbody = document.getElementById("documents-list-body");

  try {
    currentDocuments = await API.fetchDocuments(query, category);
    document.getElementById("stat-total-docs").textContent = currentDocuments.length;

    if (currentDocuments.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="text-center py-4 text-muted">
            No accessible documents found matching your filter or permissions.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = currentDocuments.map(doc => {
      const perms = doc.user_permissions || {};
      const canDownload = perms.can_download;
      const canEdit = perms.can_edit;
      const canDelete = perms.can_delete;

      return `
        <tr data-doc-id="${doc.id}">
          <td>
            <div style="display:flex; align-items:center; gap:8px;">
              <span style="font-size:1.2rem;">${getFileIcon(doc.latest_file_name)}</span>
              <div>
                <strong>${escapeHtml(doc.title)}</strong>
                <div class="text-muted" style="font-size:0.75rem;">${escapeHtml(doc.latest_file_name)}</div>
              </div>
            </div>
          </td>
          <td><span class="badge-cat">${escapeHtml(doc.category)}</span></td>
          <td><span class="badge-version">v${doc.current_version_num}</span></td>
          <td>${escapeHtml(doc.owner_name)}</td>
          <td>${formatBytes(doc.latest_file_size)}</td>
          <td>
            <span class="perm-pill ${perms.can_view ? 'active' : 'inactive'}">View</span>
            <span class="perm-pill ${canDownload ? 'active' : 'inactive'}">Download</span>
            <span class="perm-pill ${canEdit ? 'active' : 'inactive'}">Edit</span>
          </td>
          <td>${formatDate(doc.updated_at)}</td>
          <td class="text-right">
            <div class="table-actions">
              <button class="btn btn-sm btn-secondary btn-view-doc" data-id="${doc.id}" title="Preview Document">
                👁️ View
              </button>
              
              <button class="btn btn-sm ${canDownload ? 'btn-secondary' : 'btn-danger'} btn-download-doc" 
                      data-id="${doc.id}" 
                      data-can-dl="${canDownload}"
                      title="${canDownload ? 'Download Decrypted File' : 'Download Blocked for this role'}">
                ⬇️ ${canDownload ? 'Download' : 'Download (Blocked)'}
              </button>
              
              <button class="btn btn-sm btn-secondary btn-versions-doc" data-id="${doc.id}" title="Version History">
                📜 Revisions
              </button>

              ${(currentUser.role === 'ADMIN' || currentUser.role === 'MANAGER') ? `
                <button class="btn btn-sm btn-secondary btn-perms-doc" data-id="${doc.id}" title="Edit Permissions">
                  ⚙️
                </button>
              ` : ''}
            </div>
          </td>
        </tr>
      `;
    }).join("");

    attachDocActionHandlers();
  } catch (err) {
    console.error("Error fetching docs:", err);
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-red py-4">Error loading documents: ${err.message}</td></tr>`;
  }
}

function attachDocActionHandlers() {
  // View
  document.querySelectorAll(".btn-view-doc").forEach(btn => {
    btn.onclick = () => openDocumentViewer(btn.dataset.id);
  });

  // Download
  document.querySelectorAll(".btn-download-doc").forEach(btn => {
    btn.onclick = () => handleDocumentDownload(btn.dataset.id);
  });

  // Versions
  document.querySelectorAll(".btn-versions-doc").forEach(btn => {
    btn.onclick = () => openVersionsModal(btn.dataset.id);
  });

  // Permissions
  document.querySelectorAll(".btn-perms-doc").forEach(btn => {
    btn.onclick = () => openPermissionsModal(btn.dataset.id);
  });
}

/**
 * Handles Document Download & intercepts 403 Forbidden Access Denied
 */
async function handleDocumentDownload(docId, versionNum = null) {
  const token = API.getToken();
  const url = `/api/documents/${docId}/download${versionNum ? `?version_num=${versionNum}` : ''}`;

  try {
    const res = await fetch(url, {
      headers: {
        "Authorization": `Bearer ${token}`
      }
    });

    if (res.status === 403) {
      // ACCESS DENIED!
      const errorData = await res.json();
      
      // Look up document info
      const doc = currentDocuments.find(d => d.id == docId);
      const docTitle = doc ? doc.title : "Document";

      // Show the customized 403 Denied Alert Modal
      document.getElementById("denied-user").textContent = currentUser.full_name || currentUser.username;
      document.getElementById("denied-action").textContent = "Download Attempt";
      document.getElementById("denied-file").textContent = docTitle;
      document.getElementById("denied-time").textContent = new Date().toLocaleTimeString();
      document.getElementById("denied-message-text").textContent = errorData.detail || "Access Denied: You do not have permission to download this file.";

      openModal("modal-denied");

      // Play alert toast & immediately update the audit stats counter
      showToast("Access Denied (403 Forbidden): Action recorded in Audit Log", "error");
      await loadAuditStats();
      return;
    }

    if (!res.ok) {
      const errorData = await res.json();
      showToast(`Error: ${errorData.detail || "Download failed"}`, "error");
      return;
    }

    // Success: Trigger file save
    const blob = await res.blob();
    const disposition = res.headers.get("Content-Disposition");
    let filename = "download";
    if (disposition && disposition.includes("filename=")) {
      filename = disposition.split("filename=")[1].replace(/["']/g, "").trim();
    }

    const blobUrl = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(blobUrl);

    showToast(`Downloaded '${filename}' successfully!`, "success");
    await loadAuditStats();
  } catch (err) {
    showToast(`Network error: ${err.message}`, "error");
  }
}

/**
 * Open Document Viewer
 */
async function openDocumentViewer(docId) {
  try {
    const doc = await API.getDocument(docId);
    document.getElementById("viewer-title").textContent = doc.title;
    document.getElementById("viewer-meta").textContent = `v${doc.current_version_num} • ${doc.category} • ${formatBytes(doc.latest_file_size)}`;

    const token = API.getToken();
    const viewUrl = `/api/documents/${docId}/view`;

    // Fetch view stream with JWT
    const res = await fetch(viewUrl, {
      headers: { "Authorization": `Bearer ${token}` }
    });

    if (!res.ok) {
      const err = await res.json();
      showToast(`Cannot view document: ${err.detail}`, "error");
      return;
    }

    const blob = await res.blob();
    const fileUrl = URL.createObjectURL(blob);

    const iframe = document.getElementById("viewer-iframe");
    iframe.src = fileUrl;

    const btnDl = document.getElementById("btn-viewer-download");
    btnDl.onclick = () => handleDocumentDownload(docId);

    openModal("modal-viewer");
    await loadAuditStats();
  } catch (e) {
    showToast(`View failed: ${e.message}`, "error");
  }
}

/**
 * Version History Modal
 */
async function openVersionsModal(docId) {
  try {
    const doc = await API.getDocument(docId);
    document.getElementById("versions-modal-title").textContent = `📜 Revisions: ${doc.title}`;
    document.getElementById("version-doc-id").value = doc.id;

    // Show or hide new version upload based on edit permissions
    const canEdit = doc.user_permissions.can_edit;
    const uploadBox = document.getElementById("upload-new-version-box");
    uploadBox.style.display = canEdit ? "block" : "none";

    const container = document.getElementById("versions-container");
    container.innerHTML = doc.versions.map(v => {
      const isCurrent = v.version_number === doc.current_version_num;
      return `
        <div class="version-item ${isCurrent ? 'current' : ''}">
          <div class="version-item-left">
            <span class="version-badge-big">v${v.version_number}</span>
            <div class="version-details">
              <span class="version-notes">${escapeHtml(v.change_notes || 'Revision upload')} ${isCurrent ? '<span class="badge-allowed" style="font-size:0.65rem;">LATEST</span>' : ''}</span>
              <span class="version-sub">${escapeHtml(v.file_name)} • ${formatBytes(v.file_size)} • Uploaded by ${escapeHtml(v.uploaded_by_name)} on ${formatDate(v.created_at)}</span>
              <span class="version-sub" style="font-family:monospace; font-size:0.7rem; color:var(--text-muted);">SHA-256: ${v.file_hash.substring(0, 16)}...</span>
            </div>
          </div>
          <div>
            <button class="btn btn-sm btn-secondary btn-dl-ver" data-doc="${doc.id}" data-ver="${v.version_number}">
              ⬇️ Download v${v.version_number}
            </button>
          </div>
        </div>
      `;
    }).join("");

    container.querySelectorAll(".btn-dl-ver").forEach(btn => {
      btn.onclick = () => handleDocumentDownload(btn.dataset.doc, btn.dataset.ver);
    });

    openModal("modal-versions");
  } catch (e) {
    showToast(`Failed to load versions: ${e.message}`, "error");
  }
}

/**
 * Permissions Management Modal
 */
async function openPermissionsModal(docId) {
  try {
    const perms = await API.getPermissions(docId);
    const doc = currentDocuments.find(d => d.id == docId);

    document.getElementById("perm-modal-title").textContent = `🔐 Permissions: ${doc ? doc.title : 'Document'}`;
    document.getElementById("perm-doc-id").value = docId;

    const mgr = perms.find(p => p.role === "MANAGER") || {};
    const emp = perms.find(p => p.role === "EMPLOYEE") || {};

    document.getElementById("edit-perm-manager-view").checked = mgr.can_view ?? true;
    document.getElementById("edit-perm-manager-dl").checked = mgr.can_download ?? true;
    document.getElementById("edit-perm-manager-edit").checked = mgr.can_edit ?? true;
    document.getElementById("edit-perm-manager-del").checked = mgr.can_delete ?? false;

    document.getElementById("edit-perm-employee-view").checked = emp.can_view ?? true;
    document.getElementById("edit-perm-employee-dl").checked = emp.can_download ?? false;
    document.getElementById("edit-perm-employee-edit").checked = emp.can_edit ?? false;
    document.getElementById("edit-perm-employee-del").checked = emp.can_delete ?? false;

    openModal("modal-permissions");
  } catch (e) {
    showToast(`Permissions error: ${e.message}`, "error");
  }
}

/**
 * Load Audit Logs
 */
async function loadAuditLogs() {
  const status = document.getElementById("audit-status-filter").value;
  const action = document.getElementById("audit-action-filter").value;
  const username = document.getElementById("audit-user-search").value.trim();
  const tbody = document.getElementById("audit-logs-body");

  try {
    const logs = await API.fetchAuditLogs(status, action, username);

    if (logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-muted">No audit logs matching query.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(log => {
      const isDenied = log.status === "DENIED";
      return `
        <tr style="${isDenied ? 'background-color: rgba(218, 54, 51, 0.06);' : ''}">
          <td style="font-family:monospace; font-size:0.75rem;">${formatDate(log.timestamp)}</td>
          <td><span class="${isDenied ? 'badge-denied' : 'badge-allowed'}">${log.status}</span></td>
          <td><strong>${log.action}</strong></td>
          <td>${escapeHtml(log.username)}</td>
          <td><span class="role-badge ${log.user_role.toLowerCase()}">${log.user_role}</span></td>
          <td>${escapeHtml(log.document_title || '-')}</td>
          <td>${log.version_number ? `v${log.version_number}` : '-'}</td>
          <td style="font-family:monospace; font-size:0.75rem;">${escapeHtml(log.ip_address)}</td>
          <td><small>${escapeHtml(log.details)}</small></td>
        </tr>
      `;
    }).join("");
  } catch (e) {
    console.error("Audit log error:", e);
    tbody.innerHTML = `<tr><td colspan="9" class="text-center text-red py-4">Error loading audit logs: ${e.message}</td></tr>`;
  }
}

async function loadAuditStats() {
  try {
    const stats = await API.fetchAuditStats();
    document.getElementById("stat-total-events").textContent = stats.total_events;
    document.getElementById("stat-blocked-attempts").textContent = stats.denied_events;
    document.getElementById("audit-denied-badge").textContent = `${stats.denied_events} Denied`;
  } catch (e) {
    console.warn("Stats error", e);
  }
}

async function loadUsersDirectory() {
  const tbody = document.getElementById("users-table-body");
  if (!tbody) return;

  try {
    const users = await API.fetchUsers();
    if (users.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-3 text-muted">Available to Admin/Manager roles only.</td></tr>`;
      return;
    }

    tbody.innerHTML = users.map(u => `
      <tr>
        <td><strong>${escapeHtml(u.full_name)}</strong></td>
        <td><code>${escapeHtml(u.username)}</code></td>
        <td>${escapeHtml(u.email)}</td>
        <td><span class="role-badge ${u.role.toLowerCase()}">${u.role}</span></td>
        <td>${escapeHtml(u.department || 'General')}</td>
        <td>
          <button class="btn btn-sm btn-secondary btn-switch-user" data-role="${u.role}">
            Switch to ${u.username}
          </button>
        </td>
      </tr>
    `).join("");

    tbody.querySelectorAll(".btn-switch-user").forEach(btn => {
      btn.onclick = () => switchDemoRole(btn.dataset.role);
    });
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" class="text-center py-3 text-muted">Restricted directory view.</td></tr>`;
  }
}

async function switchDemoRole(role) {
  try {
    const data = await API.demoLogin(role);
    currentUser = data.user;
    updateUserBadge();
    showToast(`Switched active role to ${role} (${currentUser.full_name})`, "info");
    await refreshDashboard();
  } catch (e) {
    showToast(`Switch failed: ${e.message}`, "error");
  }
}

function setupEventListeners() {
  // Demo Role Buttons
  document.querySelectorAll(".role-btn").forEach(btn => {
    btn.addEventListener("click", () => switchDemoRole(btn.dataset.role));
  });

  // Tabs
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");

      if (btn.dataset.tab === "tab-audit") {
        loadAuditLogs();
      } else if (btn.dataset.tab === "tab-rbac") {
        loadUsersDirectory();
      }
    });
  });

  // Modal Closers
  document.querySelectorAll("[data-close]").forEach(el => {
    el.addEventListener("click", () => closeModal(el.dataset.close));
  });

  // Open Upload Modal
  document.getElementById("btn-open-upload").addEventListener("click", () => {
    if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
      showToast("Access Denied: Only Admins & Managers can upload documents", "error");
      return;
    }
    openModal("modal-upload");
  });

  // Upload Form Submit
  document.getElementById("form-upload-doc").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById("upload-file");
    if (!fileInput.files[0]) {
      showToast("Please choose a file to upload", "error");
      return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("title", document.getElementById("upload-title").value);
    formData.append("category", document.getElementById("upload-category").value);
    formData.append("description", document.getElementById("upload-description").value);

    // Initial permissions
    formData.append("admin_view", "true");
    formData.append("admin_download", "true");
    formData.append("admin_edit", "true");
    formData.append("admin_delete", "true");

    formData.append("manager_view", document.getElementById("perm-manager-view").checked);
    formData.append("manager_download", document.getElementById("perm-manager-dl").checked);
    formData.append("manager_edit", document.getElementById("perm-manager-edit").checked);
    formData.append("manager_delete", document.getElementById("perm-manager-del").checked);

    formData.append("employee_view", document.getElementById("perm-employee-view").checked);
    formData.append("employee_download", document.getElementById("perm-employee-dl").checked);
    formData.append("employee_edit", document.getElementById("perm-employee-edit").checked);
    formData.append("employee_delete", document.getElementById("perm-employee-del").checked);

    try {
      showToast("Encrypting file with AES-256 & uploading...", "info");
      await API.uploadDocument(formData);
      showToast("Document encrypted & stored successfully!", "success");
      closeModal("modal-upload");
      document.getElementById("form-upload-doc").reset();
      await refreshDashboard();
    } catch (err) {
      showToast(`Upload failed: ${err.message}`, "error");
    }
  });

  // Upload New Version Form Submit
  document.getElementById("form-upload-version").addEventListener("submit", async (e) => {
    e.preventDefault();
    const docId = document.getElementById("version-doc-id").value;
    const fileInput = document.getElementById("new-version-file");
    const notes = document.getElementById("new-version-notes").value;

    if (!fileInput.files[0]) return;

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("change_notes", notes);

    try {
      showToast("Uploading and encrypting new revision...", "info");
      await API.uploadVersion(docId, formData);
      showToast("New revision saved successfully!", "success");
      document.getElementById("form-upload-version").reset();
      await openVersionsModal(docId);
      await refreshDashboard();
    } catch (err) {
      showToast(`Version upload failed: ${err.message}`, "error");
    }
  });

  // Edit Permissions Form Submit
  document.getElementById("form-edit-permissions").addEventListener("submit", async (e) => {
    e.preventDefault();
    const docId = document.getElementById("perm-doc-id").value;

    const payload = {
      permissions: [
        {
          role: "ADMIN",
          can_view: true,
          can_download: true,
          can_edit: true,
          can_delete: true
        },
        {
          role: "MANAGER",
          can_view: document.getElementById("edit-perm-manager-view").checked,
          can_download: document.getElementById("edit-perm-manager-dl").checked,
          can_edit: document.getElementById("edit-perm-manager-edit").checked,
          can_delete: document.getElementById("edit-perm-manager-del").checked
        },
        {
          role: "EMPLOYEE",
          can_view: document.getElementById("edit-perm-employee-view").checked,
          can_download: document.getElementById("edit-perm-employee-dl").checked,
          can_edit: document.getElementById("edit-perm-employee-edit").checked,
          can_delete: document.getElementById("edit-perm-employee-del").checked
        }
      ]
    };

    try {
      await API.updatePermissions(docId, payload);
      showToast("Permissions updated & logged to audit trail!", "success");
      closeModal("modal-permissions");
      await refreshDashboard();
    } catch (err) {
      showToast(`Update error: ${err.message}`, "error");
    }
  });

  // Search & Filter Listeners
  document.getElementById("doc-search-input").addEventListener("input", debounce(loadDocuments, 300));
  document.getElementById("category-filter").addEventListener("change", loadDocuments);
  document.getElementById("btn-refresh-docs").addEventListener("click", loadDocuments);

  // Audit Filters
  document.getElementById("audit-status-filter").addEventListener("change", loadAuditLogs);
  document.getElementById("audit-action-filter").addEventListener("change", loadAuditLogs);
  document.getElementById("audit-user-search").addEventListener("input", debounce(loadAuditLogs, 300));
  document.getElementById("btn-refresh-audit").addEventListener("click", () => {
    loadAuditLogs();
    loadAuditStats();
  });

  // Navigate to audit log from Denied Modal
  document.getElementById("btn-view-denied-log").addEventListener("click", () => {
    closeModal("modal-denied");
    document.getElementById("btn-tab-audit").click();
    document.getElementById("audit-status-filter").value = "DENIED";
    loadAuditLogs();
  });

  // Logout
  document.getElementById("btn-logout").addEventListener("click", () => {
    API.clearToken();
    location.reload();
  });
}

function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.add("active");
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.remove("active");
}

function showToast(message, type = "info") {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  
  let icon = "ℹ️";
  if (type === "success") icon = "✅";
  if (type === "error") icon = "🛑";

  toast.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function getFileIcon(filename) {
  if (!filename) return "📄";
  const ext = filename.split(".").pop().toLowerCase();
  if (ext === "pdf") return "📕";
  if (["doc", "docx"].includes(ext)) return "📘";
  if (["xls", "xlsx", "csv"].includes(ext)) return "📗";
  if (["png", "jpg", "jpeg", "svg"].includes(ext)) return "🖼️";
  if (["zip", "tar", "gz"].includes(ext)) return "📦";
  return "📄";
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatDate(isoStr) {
  if (!isoStr) return "";
  const d = new Date(isoStr);
  return d.toLocaleDateString() + " " + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function debounce(fn, delay) {
  let timer = null;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), delay);
  };
}
