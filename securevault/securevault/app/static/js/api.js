/**
 * SecureVault API Client
 */
const API = {
  getToken() {
    return localStorage.getItem("securevault_token") || "";
  },

  setToken(token) {
    localStorage.setItem("securevault_token", token);
  },

  clearToken() {
    localStorage.removeItem("securevault_token");
    localStorage.removeItem("securevault_user");
  },

  getCurrentUser() {
    const raw = localStorage.getItem("securevault_user");
    try {
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  },

  setCurrentUser(user) {
    localStorage.setItem("securevault_user", JSON.stringify(user));
  },

  async request(endpoint, options = {}) {
    const headers = options.headers || {};
    const token = this.getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const config = {
      ...options,
      headers
    };

    const res = await fetch(endpoint, config);

    if (res.status === 401) {
      console.warn("Unauthorized request. Switching to fallback demo user.");
    }

    return res;
  },

  async demoLogin(role) {
    const res = await fetch(`/api/auth/demo-login/${role}`);
    if (!res.ok) throw new Error(`Demo login for ${role} failed`);
    const data = await res.json();
    this.setToken(data.access_token);
    this.setCurrentUser(data.user);
    return data;
  },

  async fetchDocuments(query = "", category = "") {
    const params = new URLSearchParams();
    if (query) params.append("query", query);
    if (category && category !== "All") params.append("category", category);

    const res = await this.request(`/api/documents?${params.toString()}`);
    if (!res.ok) throw new Error("Failed to load documents");
    return res.json();
  },

  async getDocument(id) {
    const res = await this.request(`/api/documents/${id}`);
    if (!res.ok) throw new Error("Failed to load document details");
    return res.json();
  },

  async uploadDocument(formData) {
    const res = await this.request("/api/documents/upload", {
      method: "POST",
      body: formData
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Upload failed");
    }
    return res.json();
  },

  async uploadVersion(docId, formData) {
    const res = await this.request(`/api/documents/${docId}/versions`, {
      method: "POST",
      body: formData
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Version upload failed");
    }
    return res.json();
  },

  async getPermissions(docId) {
    const res = await this.request(`/api/documents/${docId}/permissions`);
    if (!res.ok) throw new Error("Failed to load permissions");
    return res.json();
  },

  async updatePermissions(docId, payload) {
    const res = await this.request(`/api/documents/${docId}/permissions`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to update permissions");
    }
    return res.json();
  },

  async fetchAuditLogs(status = "ALL", action = "ALL", username = "") {
    const params = new URLSearchParams();
    if (status && status !== "ALL") params.append("status", status);
    if (action && action !== "ALL") params.append("action", action);
    if (username) params.append("username", username);

    const res = await this.request(`/api/audit/logs?${params.toString()}`);
    if (!res.ok) throw new Error("Failed to load audit logs");
    return res.json();
  },

  async fetchAuditStats() {
    const res = await this.request("/api/audit/stats");
    if (!res.ok) return { total_events: 0, allowed_events: 0, denied_events: 0, downloads_blocked: 0 };
    return res.json();
  },

  async fetchUsers() {
    const res = await this.request("/api/users");
    if (!res.ok) return [];
    return res.json();
  }
};
