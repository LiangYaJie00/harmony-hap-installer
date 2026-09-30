const $ = (id) => document.getElementById(id);
let artifact = null;
let selectedDevice = "";
let busy = false;

const RESULT_LABEL = {
  INSTALLED: "已安装",
  FAILED: "未安装",
  VERIFY_FAILED: "核对失败",
  UNKNOWN: "结果未知",
  CANCELED: "已取消",
};

async function invoke(command, args) {
  if (!window.__TAURI__ || !window.__TAURI__.core) {
    throw new Error("请在桌面窗口中打开这个工具");
  }
  return window.__TAURI__.core.invoke(command, args || {});
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[ch]));
}

function formatSize(bytes) {
  const size = Number(bytes);
  if (!Number.isFinite(size) || size < 0) return "大小未知";
  if (size < 1024) return `${size} B`;
  const units = ["KB", "MB", "GB"];
  let value = size / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  const digits = value >= 100 ? 0 : 1;
  return `${value.toFixed(digits)} ${units[index]}`;
}

function formatVersion(name, code) {
  const body = !name
    ? "未知"
    : code === undefined || code === null || code === ""
      ? String(name)
      : `${name}(${code})`;
  return `版本号：${body}`;
}

function formatBundle(name) {
  return `包名：${name || "未读取"}`;
}

function deviceLabel(device) {
  const name = String(device.modelName || "").trim() || transportLabel(device.transport);
  return `${name}[${device.id}]`;
}

function formatTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (value) => String(value).padStart(2, "0");
  return `${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function shorten(value) {
  const text = String(value || "");
  if (text.length <= 20) return text || "未能读取";
  return `${text.slice(0, 8)}…${text.slice(-8)}`;
}

function transportLabel(value) {
  const text = String(value || "").toUpperCase();
  if (text.includes("USB")) return "USB 连接";
  if (text.includes("TCP") || text.includes("WLAN") || text.includes("WIFI") || text.includes("WIRELESS")) return "无线调试";
  return value ? `连接方式 ${value}` : "连接方式未知";
}

function stateBadge(state) {
  if (state === "在线") return { className: "ok", label: "可安装" };
  if (state === "未授权") return { className: "warn", label: "未授权" };
  if (state === "离线") return { className: "muted", label: "已离线" };
  return { className: "muted", label: state || "状态未知" };
}

const PAGE_ORDER = { home: 0, detail: 1, result: 2 };
let currentPage = "home";
let pendingEnter = "";

function show(id) {
  const forward = (PAGE_ORDER[id] ?? 0) >= (PAGE_ORDER[currentPage] ?? 0);
  for (const section of ["home", "detail", "result"]) $(section).hidden = section !== id;
  const changed = currentPage !== id;
  currentPage = id;
  setBanner("");
  if (!changed) return;
  const motion = forward ? "enter-forward" : "enter-back";
  if (busy) {
    pendingEnter = motion;
    return;
  }
  playEnter(id, motion);
}

function playEnter(id, motion) {
  const section = $(id);
  section.classList.remove("enter-forward", "enter-back");
  void section.offsetWidth;
  section.classList.add(motion);
}

function setBanner(text) {
  $("banner").hidden = !text;
  $("banner").textContent = text || "";
}

function paint() {
  return new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
}

function setBusy(title, detail, progress) {
  busy = Boolean(title);
  const overlay = $("overlay");
  overlay.hidden = !busy;
  if (!busy) {
    updateInstallButton();
    if (pendingEnter) {
      const motion = pendingEnter;
      pendingEnter = "";
      playEnter(currentPage, motion);
    }
    return;
  }
  $("overlay-title").textContent = title;
  $("overlay-detail").textContent = detail || "请稍候，正在处理";
  const bar = $("overlay-bar");
  if (typeof progress === "number") {
    bar.classList.remove("indeterminate");
    bar.style.width = `${Math.max(4, Math.min(100, Math.round(progress * 100)))}%`;
  } else {
    bar.classList.add("indeterminate");
    bar.style.width = "";
  }
}

async function bytesOf(file, title) {
  setBusy(title, file.name, 0);
  await paint();
  const view = new Uint8Array(await file.arrayBuffer());
  const out = new Array(view.length);
  const step = 256 * 1024;
  for (let index = 0; index < view.length; index += step) {
    const end = Math.min(index + step, view.length);
    for (let cursor = index; cursor < end; cursor += 1) out[cursor] = view[cursor];
    const ratio = view.length ? end / view.length : 1;
    setBusy(title, `${file.name} · ${Math.round(ratio * 100)}%`, ratio);
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return out;
}

function errorText(error) {
  const message = error?.message || String(error);
  return error?.suggestion ? `${message}\n${error.suggestion}` : message;
}

function fillIdentity(policy) {
  $("enforce").checked = Boolean(policy.enforce);
  $("domains").value = (policy.allowedDomains || []).join("\n");
  $("bundles").value = (policy.allowedBundleNames || []).join("\n");
  $("certs").value = (policy.certificates || [])
    .map((cert) => `${cert.fingerprintSha256} ${cert.notAfter}`)
    .join("\n");
}

function readIdentity() {
  const lines = (id) => $(id).value.split(/\n/).map((item) => item.trim()).filter(Boolean);
  return {
    enforce: $("enforce").checked,
    allowedDomains: lines("domains"),
    allowedBundleNames: lines("bundles"),
    certificates: lines("certs").map((line) => {
      const parts = line.split(/[\s,]+/);
      return { fingerprintSha256: parts[0] || "", notAfter: parts[1] || "" };
    }),
  };
}

async function refreshStatus() {
  const doctor = await invoke("doctor");
  $("hdc-pill").textContent = doctor.gaps.length ? "HDC 需要处理" : `HDC ${doctor.hdcVersion} 可用`;
  $("hdc-pill").className = doctor.gaps.length ? "pill warn" : "pill";
  $("hdc-path").textContent = doctor.hdcPath ? `内置 HDC：${doctor.hdcVersion} · ${doctor.hdcPath}` : "";
  $("identity-note").textContent = doctor.identityNote;
  if (doctor.gaps.length) setBanner(doctor.gaps.join("；"));
  const history = await invoke("history");
  const items = history.slice(-8).reverse();
  $("history").innerHTML = items.length
    ? items.map((item) => {
      const label = RESULT_LABEL[item.result] || item.result;
      const ok = item.result === "INSTALLED";
      return `<li>
        <span class="history-main">
          <strong>${escapeHtml(formatBundle(item.bundleName))}</strong>
          <span>${escapeHtml(formatVersion(item.versionName, item.versionCode))} · ${escapeHtml(formatTime(item.at))}</span>
        </span>
        <span class="badge ${ok ? "ok" : "bad"}">${escapeHtml(label)}</span>
      </li>`;
    }).join("")
    : `<li class="empty">还没有安装记录</li>`;
}

function showArtifact(next) {
  artifact = next;
  selectedDevice = "";
  const source = next.sourceHost && next.sourceHost !== "本地文件" ? `来自 ${next.sourceHost}` : "本地文件";
  $("package-source").textContent = source;
  $("package-name").textContent = formatBundle(next.bundleName);
  $("package-version").textContent = formatVersion(next.versionName, next.versionCode);
  $("package-stats").innerHTML = [
    `<li>大小 ${escapeHtml(formatSize(next.size))}</li>`,
    `<li>${escapeHtml(source)}</li>`,
    `<li>证书 ${escapeHtml(shorten(next.certificateSha256))}</li>`,
  ].join("");
  $("package-note").textContent = next.hashNote || "";
  const rows = [
    ["文件", next.fileName],
    ["任务", next.taskId || "无"],
    ["SHA-256", next.sha256],
    ["证书指纹", next.certificateSha256 || "未能读取"],
  ];
  $("artifact").innerHTML = rows
    .map(([name, value]) => `<dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd>`)
    .join("");
  show("detail");
}

async function refreshDevices() {
  const view = await invoke("devices");
  const online = view.devices.filter((device) => device.state === "在线");
  if (!view.devices.length) {
    $("device-hint").textContent = "还没有设备。用数据线连接手机，打开开发者选项中的 USB 调试，并在手机上允许这台电脑调试。";
  } else if (view.requiresChoice && online.length > 1) {
    $("device-hint").textContent = "连接了多台设备，请选择要安装的那一台。";
  } else if (!online.length) {
    $("device-hint").textContent = "设备已连接，但还不能安装。未授权时，请在手机上允许调试。";
  } else {
    $("device-hint").textContent = "只能安装到状态为可安装的设备。";
  }
  $("devices").innerHTML = view.devices.length
    ? view.devices.map((device) => {
      const badge = stateBadge(device.state);
      const enabled = device.state === "在线";
      const checked = device.selected && enabled;
      if (checked) selectedDevice = device.id;
      return `<label class="device${checked ? " selected" : ""}${enabled ? "" : " disabled"}">
        <input type="radio" name="device" value="${escapeHtml(device.id)}" data-state="${escapeHtml(device.state)}" ${checked ? "checked" : ""} ${enabled ? "" : "disabled"} />
        <span class="device-main">
          <span class="device-title">${escapeHtml(deviceLabel(device))}</span>
          <span class="device-tail">${escapeHtml(transportLabel(device.transport))}</span>
        </span>
        <span class="badge ${badge.className}">${escapeHtml(badge.label)}</span>
      </label>`;
    }).join("")
    : `<p class="empty">没有发现设备</p>`;
  document.querySelectorAll('input[name="device"]').forEach((input) => {
    input.addEventListener("change", () => {
      document.querySelectorAll(".device").forEach((card) => card.classList.remove("selected"));
      input.closest(".device").classList.add("selected");
      selectedDevice = input.value;
      updateInstallButton();
    });
  });
  updateInstallButton();
}

function selectedDeviceLabel() {
  const selected = document.querySelector('input[name="device"]:checked');
  return selected?.closest(".device")?.querySelector(".device-title")?.textContent || "";
}

function updateInstallButton() {
  const selected = document.querySelector('input[name="device"]:checked');
  const ready = Boolean(selected && selected.dataset.state === "在线" && !busy);
  $("install").disabled = !ready;
  $("install").textContent = ready ? "安装到这台设备" : "请选择一台可安装的设备";
}

function showResult({ ok, title, body, canLaunch, canRetry }) {
  $("result").classList.toggle("ok", ok);
  $("result").classList.toggle("bad", !ok);
  $("result-kicker").textContent = ok ? "安装完成" : "没有安装成功";
  $("result-title").textContent = title;
  $("result-body").textContent = body || "";
  $("launch").hidden = !canLaunch;
  $("retry").hidden = !canRetry;
  show("result");
}

async function resolveUrl() {
  if (busy) return;
  const url = $("url").value.trim();
  if (!url) {
    setBanner("先粘贴或输入下载链接");
    return;
  }
  setBusy("正在解析链接", "正在下载并校验安装包");
  await paint();
  try {
    const outcome = await invoke("resolve_url", { url });
    if (outcome.landingUrl) {
      await invoke("open_url", { url: outcome.landingUrl });
      showResult({ ok: false, title: "这是下载页面", body: outcome.landingMessage, canLaunch: false, canRetry: false });
      return;
    }
    setBusy("正在检查设备", "查找已连接的鸿蒙设备");
    showArtifact(outcome.artifact);
    await refreshDevices();
  } catch (error) {
    showResult({ ok: false, title: "链接没有解析成功", body: errorText(error), canLaunch: false, canRetry: false });
  } finally {
    setBusy("");
  }
}

$("paste").onclick = async () => {
  try {
    $("url").value = (await navigator.clipboard.readText()).trim();
    setBanner("");
  } catch (error) {
    setBanner("没有读到剪贴板，请手动粘贴链接");
  }
};
$("url").addEventListener("keydown", (event) => {
  if (event.key === "Enter") resolveUrl();
});
$("use-url").onclick = () => resolveUrl();
$("qr").onchange = async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file || busy) return;
  try {
    const bytes = await bytesOf(file, "正在识别二维码");
    setBusy("正在解析二维码", file.name);
    await paint();
    const outcome = await invoke("resolve_qr", { bytes });
    if (outcome.landingUrl) {
      await invoke("open_url", { url: outcome.landingUrl });
      showResult({ ok: false, title: "二维码是下载页面", body: outcome.landingMessage, canLaunch: false, canRetry: false });
      return;
    }
    setBusy("正在检查设备", "查找已连接的鸿蒙设备");
    showArtifact(outcome.artifact);
    await refreshDevices();
  } catch (error) {
    showResult({ ok: false, title: "二维码没有识别成功", body: errorText(error), canLaunch: false, canRetry: false });
  } finally {
    setBusy("");
  }
};
$("hap").onchange = async (event) => {
  const file = event.target.files[0];
  event.target.value = "";
  if (!file || busy) return;
  try {
    const bytes = await bytesOf(file, "正在读取安装包");
    setBusy("正在校验安装包", file.name);
    await paint();
    showArtifact(await invoke("resolve_local_bytes", { fileName: file.name, bytes }));
    setBusy("正在检查设备", "查找已连接的鸿蒙设备");
    await refreshDevices();
  } catch (error) {
    showResult({ ok: false, title: "这个文件不能安装", body: errorText(error), canLaunch: false, canRetry: false });
  } finally {
    setBusy("");
  }
};
$("refresh-devices").onclick = () => {
  refreshDevices().catch((error) => setBanner(errorText(error)));
};
$("back").onclick = async () => {
  show("home");
  await refreshStatus().catch((error) => setBanner(errorText(error)));
};
$("install").onclick = async () => {
  if (busy || !artifact || !selectedDevice) return;
  setBusy("正在安装", "请保持设备和电脑的连接，安装完成后会自动进入结果页");
  await paint();
  try {
    const result = await invoke("install", { sha256: artifact.sha256, deviceId: selectedDevice, confirm: true });
    showResult({
      ok: true,
      title: result.message || "安装成功",
      body: `${formatBundle(result.bundleName)}\n${formatVersion(result.versionName, result.versionCode)}\n${result.mode} · ${selectedDeviceLabel()}`,
      canLaunch: Boolean(artifact.abilityName),
      canRetry: false,
    });
    await refreshStatus();
  } catch (error) {
    showResult({
      ok: false,
      title: "安装没有完成",
      body: errorText(error),
      canLaunch: false,
      canRetry: true,
    });
  } finally {
    setBusy("");
  }
};
$("retry").onclick = async () => {
  show("detail");
  await refreshDevices().catch((error) => setBanner(errorText(error)));
};
$("launch").onclick = async () => {
  setBusy("正在打开应用", artifact?.bundleName || "");
  await paint();
  try {
    await invoke("launch", { deviceId: selectedDevice, bundleName: artifact.bundleName, ability: artifact.abilityName });
    setBanner("");
    $("result-body").textContent = `${$("result-body").textContent}\n已向设备发送打开请求`;
  } catch (error) {
    setBanner(errorText(error));
  } finally {
    setBusy("");
  }
};
$("copy").onclick = async () => {
  const text = await invoke("diagnostics");
  await navigator.clipboard.writeText(text);
  $("copy").textContent = "已复制";
  setTimeout(() => {
    $("copy").textContent = "复制诊断信息";
  }, 1600);
};
$("save-identity").onclick = async () => {
  try {
    const saved = await invoke("save_identity", { policy: readIdentity() });
    fillIdentity(saved);
    await refreshStatus();
    setBanner("高级设置已保存");
  } catch (error) {
    setBanner(errorText(error));
  }
};
$("again").onclick = async () => {
  show("home");
  await refreshStatus().catch((error) => setBanner(errorText(error)));
};

refreshStatus()
  .then(() => invoke("identity").then(fillIdentity))
  .catch((error) => {
    $("hdc-pill").textContent = "HDC 不可用";
    $("hdc-pill").className = "pill bad";
    setBanner(errorText(error));
  });
