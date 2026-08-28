    if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost")) {
      navigator.serviceWorker.register("./sw.js").then((registration) => {
        const showUpdate = (worker) => {
          const banner = document.getElementById("update-banner");
          const button = document.getElementById("update-btn");
          if (!banner || !button) return;
          banner.classList.add("show");
          button.onclick = () => { button.disabled = true; worker.postMessage({ type: "SKIP_WAITING" }); };
        };
        if (registration.waiting) showUpdate(registration.waiting);
        registration.addEventListener("updatefound", () => {
          const worker = registration.installing;
          if (worker) worker.addEventListener("statechange", () => {
            if (worker.state === "installed" && navigator.serviceWorker.controller) showUpdate(worker);
          });
        });
      }).catch(() => {});
      let refreshing = false;
      navigator.serviceWorker.addEventListener("controllerchange", () => {
        if (!refreshing) { refreshing = true; window.location.reload(); }
      });
    }

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    async function deriveKey(password, salt) {
      const keyMaterial = await crypto.subtle.importKey(
        "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
      );
      return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
      );
    }

    async function encrypt(data, key) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(data)));
      const combined = new Uint8Array(iv.length + encrypted.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(encrypted), iv.length);
      return btoa(String.fromCharCode(...combined));
    }

    async function decrypt(cipherText, key) {
      const combined = Uint8Array.from(atob(cipherText), (c) => c.charCodeAt(0));
      const iv = combined.slice(0, 12);
      const data = combined.slice(12);
      const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
      return JSON.parse(decoder.decode(decrypted));
    }

    let masterKey = null;
    let entries = [];
    let isSetup = false;

    const lockScreen = document.getElementById("lock-screen");
    const app = document.getElementById("app");
    const masterPasswordInput = document.getElementById("master-password");
    const confirmGroup = document.getElementById("confirm-group");
    const confirmPasswordInput = document.getElementById("confirm-password");
    const unlockBtn = document.getElementById("unlock-btn");
    const lockError = document.getElementById("lock-error");
    const lockTitle = document.getElementById("lock-title");
    const lockSubtitle = document.getElementById("lock-subtitle");

    const searchInput = document.getElementById("search-input");
    const addBtn = document.getElementById("add-btn");
    const lockBtn = document.getElementById("lock-btn");
    const entriesList = document.getElementById("entries-list");
    const statTotal = document.getElementById("stat-total");
    const statShown = document.getElementById("stat-shown");

    const entryModal = document.getElementById("entry-modal");
    const modalTitle = document.getElementById("modal-title");
    const modalClose = document.getElementById("modal-close");
    const modalCancel = document.getElementById("modal-cancel");
    const modalSave = document.getElementById("modal-save");
    const editId = document.getElementById("edit-id");
    const entryTitle = document.getElementById("entry-title");
    const entryUsername = document.getElementById("entry-username");
    const entryPassword = document.getElementById("entry-password");
    const entryUrl = document.getElementById("entry-url");
    const entryNotes = document.getElementById("entry-notes");
    const genPasswordBtn = document.getElementById("gen-password");
    const strengthBar = document.getElementById("strength-bar");

    function checkSetup() {
      isSetup = localStorage.getItem("pv_vault") !== null && localStorage.getItem("pv_salt") !== null;
      if (!isSetup) {
        lockTitle.textContent = "Create Vault";
        lockSubtitle.textContent = "Set a strong master password. It cannot be recovered.";
        confirmGroup.style.display = "block";
        unlockBtn.textContent = "Create Vault";
      } else {
        lockTitle.textContent = "Password Vault";
        lockSubtitle.textContent = "Enter your master password to unlock";
        confirmGroup.style.display = "none";
        unlockBtn.textContent = "Unlock";
      }
    }
    checkSetup();

    unlockBtn.addEventListener("click", handleUnlock);
    masterPasswordInput.addEventListener("keydown", (e) => { if (e.key === "Enter") handleUnlock(); });
    confirmPasswordInput.addEventListener("keydown", (e) => { if (e.key === "Enter") handleUnlock(); });

    async function handleUnlock() {
      const pwd = masterPasswordInput.value;
      lockError.textContent = "";

      if (!pwd || pwd.length < 6) {
        lockError.textContent = "Password must be at least 6 characters.";
        return;
      }

      if (!isSetup) {
        if (pwd !== confirmPasswordInput.value) {
          lockError.textContent = "Passwords do not match.";
          return;
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        localStorage.setItem("pv_salt", btoa(String.fromCharCode(...salt)));
        masterKey = await deriveKey(pwd, salt);
        entries = [];
        await saveVault();
        openApp();
      } else {
        try {
          const salt = Uint8Array.from(atob(localStorage.getItem("pv_salt")), (c) => c.charCodeAt(0));
          masterKey = await deriveKey(pwd, salt);
          entries = await decrypt(localStorage.getItem("pv_vault"), masterKey);
          openApp();
        } catch (err) {
          lockError.textContent = "Wrong master password.";
          masterKey = null;
        }
      }
    }

    function openApp() {
      lockScreen.classList.add("hide");
      setTimeout(() => {
        app.classList.add("show");
      }, 200);
      masterPasswordInput.value = "";
      confirmPasswordInput.value = "";
      renderEntries();
    }

    async function saveVault() {
      if (!masterKey) return;
      const cipher = await encrypt(entries, masterKey);
      localStorage.setItem("pv_vault", cipher);
    }

    function renderEntries(filter = "") {
      const q = filter.toLowerCase().trim();
      const filtered = entries.filter((e) =>
        e.title.toLowerCase().includes(q) ||
        e.username.toLowerCase().includes(q) ||
        (e.url || "").toLowerCase().includes(q) ||
        (e.notes || "").toLowerCase().includes(q)
      );

      statTotal.textContent = entries.length;
      statShown.textContent = filtered.length;

      if (filtered.length === 0) {
        entriesList.innerHTML = `
          <div class="empty-state">
            <p>${entries.length === 0 ? "No passwords saved yet. Click “+ Add Entry” to begin." : "No matching entries found."}</p>
          </div>`;
        return;
      }

      entriesList.innerHTML = filtered.map((e, index) => {
        const masked = "•".repeat(Math.min(e.password.length, 12));
        return `
        <div class="entry-card" data-id="${e.id}" style="animation-delay: ${index * 0.05}s">
          <div class="entry-info">
            <h3>${escapeHtml(e.title)}</h3>
            <div class="username">${escapeHtml(e.username)}</div>
            <div class="password-row">
              <span class="password-display" data-real="${escapeAttr(e.password)}">${masked}</span>
              <button class="btn btn-secondary btn-sm toggle-pw">Show</button>
              <button class="btn btn-secondary btn-sm copy-pw">Copy</button>
              ${e.url ? `<a href="${escapeAttr(e.url)}" target="_blank" rel="noopener" class="btn btn-secondary btn-sm">Visit</a>` : ""}
            </div>
          </div>
          <div class="entry-actions">
            <button class="btn btn-secondary btn-sm edit-btn">Edit</button>
            <button class="btn btn-danger btn-sm delete-btn">Delete</button>
          </div>
        </div>`;
      }).join("");

      entriesList.querySelectorAll(".toggle-pw").forEach((btn) => {
        btn.addEventListener("click", () => {
          const span = btn.parentElement.querySelector(".password-display");
          const real = span.dataset.real;
          if (span.textContent.includes("•")) {
            span.textContent = real;
            btn.textContent = "Hide";
          } else {
            span.textContent = "•".repeat(Math.min(real.length, 12));
            btn.textContent = "Show";
          }
        });
      });

      entriesList.querySelectorAll(".copy-pw").forEach((btn) => {
        btn.addEventListener("click", () => {
          const span = btn.parentElement.querySelector(".password-display");
          navigator.clipboard.writeText(span.dataset.real).then(() => {
            showToast("Password copied to clipboard!", true);
          });
        });
      });

      entriesList.querySelectorAll(".edit-btn").forEach((btn) => {
        btn.addEventListener("click", () => openEditModal(btn.closest(".entry-card").dataset.id));
      });

      entriesList.querySelectorAll(".delete-btn").forEach((btn) => {
        btn.addEventListener("click", async () => {
          const id = btn.closest(".entry-card").dataset.id;
          if (confirm("Delete this entry?")) {
            entries = entries.filter((e) => e.id !== id);
            await saveVault();
            renderEntries(searchInput.value);
            showToast("Entry deleted");
          }
        });
      });
    }

    function escapeHtml(str) {
      return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    function escapeAttr(str) {
      return String(str).replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    }

    searchInput.addEventListener("input", () => renderEntries(searchInput.value));

    addBtn.addEventListener("click", openAddModal);
    modalClose.addEventListener("click", closeModal);
    modalCancel.addEventListener("click", closeModal);
    entryModal.addEventListener("click", (e) => { if (e.target === entryModal) closeModal(); });

    function openAddModal() {
      modalTitle.textContent = "Add Entry";
      editId.value = "";
      entryTitle.value = "";
      entryUsername.value = "";
      entryPassword.value = "";
      entryUrl.value = "";
      entryNotes.value = "";
      updateStrength("");
      entryModal.classList.add("active");
      entryTitle.focus();
    }

    function openEditModal(id) {
      const e = entries.find((x) => x.id === id);
      if (!e) return;
      modalTitle.textContent = "Edit Entry";
      editId.value = e.id;
      entryTitle.value = e.title;
      entryUsername.value = e.username;
      entryPassword.value = e.password;
      entryUrl.value = e.url || "";
      entryNotes.value = e.notes || "";
      updateStrength(e.password);
      entryModal.classList.add("active");
    }

    function closeModal() {
      entryModal.classList.remove("active");
    }

    modalSave.addEventListener("click", async () => {
      const title = entryTitle.value.trim();
      const username = entryUsername.value.trim();
      const password = entryPassword.value;

      if (!title || !password) {
        showToast("Title and password are required");
        return;
      }

      const id = editId.value;
      if (id) {
        const idx = entries.findIndex((e) => e.id === id);
        if (idx !== -1) {
          entries[idx] = { ...entries[idx], title, username, password, url: entryUrl.value.trim(), notes: entryNotes.value.trim() };
        }
      } else {
        entries.push({ id: crypto.randomUUID(), title, username, password, url: entryUrl.value.trim(), notes: entryNotes.value.trim(), created: Date.now() });
      }

      await saveVault();
      closeModal();
      renderEntries(searchInput.value);
      showToast(id ? "Entry updated" : "Entry added", true);
    });

    genPasswordBtn.addEventListener("click", () => {
      const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}";
      let pw = "";
      const arr = new Uint32Array(16);
      crypto.getRandomValues(arr);
      for (let i = 0; i < 16; i++) { pw += chars[arr[i] % chars.length]; }
      entryPassword.value = pw;
      updateStrength(pw);
    });

    entryPassword.addEventListener("input", () => updateStrength(entryPassword.value));

    function updateStrength(pw) {
      let score = 0;
      if (pw.length >= 8) score += 25;
      if (pw.length >= 12) score += 15;
      if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score += 20;
      if (/\d/.test(pw)) score += 20;
      if (/[^a-zA-Z0-9]/.test(pw)) score += 20;
      strengthBar.style.width = score + "%";
      if (score < 40) strengthBar.style.background = "var(--danger)";
      else if (score < 70) strengthBar.style.background = "var(--warning)";
      else strengthBar.style.background = "var(--success)";
    }

    lockBtn.addEventListener("click", () => {
      masterKey = null;
      entries = [];
      app.classList.remove("show");
      setTimeout(() => {
        app.style.display = "none";
        lockScreen.classList.remove("hide");
        checkSetup();
        masterPasswordInput.focus();
      }, 300);
    });

    function showToast(msg, success = false) {
      const toast = document.getElementById("toast");
      toast.textContent = msg;
      toast.className = "toast show" + (success ? " success" : "");
      setTimeout(() => toast.classList.remove("show"), 2200);
    }

    masterPasswordInput.focus();
