"use strict";

const ui = {
  form: document.getElementById("run-form"),
  repository: document.getElementById("repository"),
  goal: document.getElementById("goal"),
  image: document.getElementById("image"),
  output: document.getElementById("output"),
  approvals: document.getElementById("approvals"),
  network: document.getElementById("network"),
  runButton: document.getElementById("run-button"),
  runButtonLabel: document.getElementById("run-button-label"),
  formStatus: document.getElementById("form-status"),
  shadowWarning: document.getElementById("shadow-warning"),
  dockerPill: document.getElementById("docker-pill"),
  dockerLabel: document.getElementById("docker-label"),
  truthBanner: document.getElementById("truth-banner"),
  truthTitle: document.getElementById("truth-title"),
  truthCopy: document.getElementById("truth-copy"),
  elapsed: document.getElementById("elapsed"),
  download: document.getElementById("download-report"),
  gateCard: document.getElementById("gate-card"),
  gateValue: document.getElementById("gate-value"),
  gateDetail: document.getElementById("gate-detail"),
  outcomeCard: document.getElementById("outcome-card"),
  outcomeValue: document.getElementById("outcome-value"),
  outcomeDetail: document.getElementById("outcome-detail"),
  riskDial: document.getElementById("risk-dial"),
  riskValue: document.getElementById("risk-value"),
  riskLabel: document.getElementById("risk-label"),
  allowCount: document.getElementById("allow-count"),
  denyCount: document.getElementById("deny-count"),
  pendingCount: document.getElementById("pending-count"),
  signalCount: document.getElementById("signal-count"),
  priorityList: document.getElementById("priority-list"),
  findings: document.getElementById("tab-findings"),
  authority: document.getElementById("tab-authority"),
  runtime: document.getElementById("tab-runtime"),
  rawReport: document.getElementById("raw-report")
};

const labels = {
  gate: {
    pass: "통과",
    fail: "차단",
    inconclusive: "판단 보류",
    not_evaluated: "미평가"
  },
  verdict: {
    safe: "안전 확인",
    review: "검토 필요",
    unsafe: "위험 확인",
    inconclusive: "판단 불가"
  },
  outcome: {
    analyzed: "분석 완료",
    planned: "실행 계획 생성",
    succeeded: "실행 성공",
    failed: "실행 실패",
    blocked: "정책 차단",
    awaiting_approval: "승인 필요",
    runtime_unavailable: "실행 환경 없음"
  },
  decision: {
    allow: "허용",
    deny: "차단",
    require_approval: "승인 필요"
  },
  source: {
    target_telemetry: "대상 텔레메트리",
    supervisor: "감독기",
    independent_observer: "독립 관찰자"
  }
};

let sessionToken = "";
let currentReport = null;
let timerId = null;
let startedAt = 0;

function safeSessionToken() {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const fromFragment = fragment.get("token");
  if (fromFragment) {
    sessionStorage.setItem("r-sandbox-session", fromFragment);
    history.replaceState(null, "", window.location.pathname);
  }
  return sessionStorage.getItem("r-sandbox-session") || "";
}

async function api(path, options) {
  const config = options || {};
  const headers = new Headers(config.headers || {});
  headers.set("X-R-Sandbox-Token", sessionToken);
  const response = await fetch(path, {
    method: config.method || "GET",
    body: config.body,
    headers: headers,
    cache: "no-store",
    credentials: "omit"
  });
  let payload = {};
  try {
    payload = await response.json();
  } catch (_error) {
    payload = {error: "서버 응답을 읽을 수 없습니다."};
  }
  if (!response.ok) {
    throw new Error(payload.error || "요청을 완료하지 못했습니다.");
  }
  return payload;
}

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (value !== undefined && value !== null) {
    node.textContent = String(value);
  }
  return node;
}

function emptyPanel(message) {
  const box = element("div", "empty-detail", message);
  return box;
}

function splitValues(value) {
  return value
    .split(/[\n,]+/)
    .map(function (item) { return item.trim(); })
    .filter(Boolean);
}

function selectedMode() {
  const input = document.querySelector('input[name="mode"]:checked');
  return input ? input.value : "analyze";
}

function updateMode() {
  const isShadow = selectedMode() === "shadow";
  ui.shadowWarning.hidden = !isShadow;
  ui.runButtonLabel.textContent = isShadow ? "격리 검사 시작" : "보안 검사 시작";
}

function setBusy(isBusy) {
  ui.runButton.disabled = isBusy;
  document.querySelectorAll("#run-form input, #run-form textarea").forEach(function (node) {
    node.disabled = isBusy;
  });
  if (isBusy) {
    startedAt = Date.now();
    ui.truthBanner.dataset.state = "running";
    ui.truthTitle.textContent = "에이전트 실행 중";
    ui.truthCopy.textContent = "저장소를 이해하고 최소 권한 계약을 계산하고 있습니다.";
    ui.formStatus.textContent = "페이지를 닫지 말고 완료될 때까지 기다려 주세요.";
    ui.runButtonLabel.textContent = "검사 진행 중";
    document.querySelectorAll(".pipeline li").forEach(function (item) {
      item.classList.remove("done");
      item.classList.add("active");
    });
    timerId = window.setInterval(function () {
      ui.elapsed.textContent = ((Date.now() - startedAt) / 1000).toFixed(1) + "초";
    }, 100);
  } else {
    if (timerId !== null) {
      window.clearInterval(timerId);
      timerId = null;
    }
    document.querySelectorAll("#run-form input, #run-form textarea").forEach(function (node) {
      node.disabled = false;
    });
    ui.runButton.disabled = false;
    updateMode();
  }
}

function stateForGate(gate) {
  if (gate === "pass") {
    return "pass";
  }
  if (gate === "fail") {
    return "danger";
  }
  return "warning";
}

function renderPipeline(report) {
  const completed = new Set(
    (report.timeline || []).map(function (record) { return record.phase; })
  );
  document.querySelectorAll(".pipeline li").forEach(function (item) {
    item.classList.remove("active");
    item.classList.toggle("done", completed.has(item.dataset.phase));
  });
}

function renderSummary(report, elapsedSeconds) {
  const assessment = report.security_assessment || {};
  const gate = report.security_gate_result || "not_evaluated";
  const verdict = assessment.verdict || "inconclusive";
  const outcome = report.outcome || "analyzed";
  const execution = report.execution;
  const gateState = stateForGate(gate);

  ui.gateCard.dataset.state = gateState;
  ui.gateValue.textContent = labels.gate[gate] || gate;
  ui.gateDetail.textContent = (labels.verdict[verdict] || verdict) + " · " +
    (assessment.summary || "평가 근거 없음");

  ui.outcomeCard.dataset.state =
    outcome === "succeeded" ? "pass" :
    (outcome === "failed" || outcome === "blocked" ? "danger" : "warning");
  ui.outcomeValue.textContent = labels.outcome[outcome] || outcome;
  if (execution && execution.exit_code !== null) {
    ui.outcomeDetail.textContent =
      "프로세스 종료 " + String(execution.exit_code) + " · " +
      Number(execution.duration_seconds || 0).toFixed(2) + "초";
  } else if (outcome === "planned") {
    ui.outcomeDetail.textContent = "명령만 생성했으며 연구 코드는 실행하지 않았습니다.";
  } else if (outcome === "runtime_unavailable") {
    ui.outcomeDetail.textContent = "Docker 실행 환경을 사용할 수 없어 시작하지 못했습니다.";
  } else if (outcome === "blocked") {
    ui.outcomeDetail.textContent = "실행 전 정책 또는 샌드박스 경계에서 차단됐습니다.";
  } else if (outcome === "awaiting_approval") {
    ui.outcomeDetail.textContent = "필요한 권한이 승인되지 않아 실행하지 않았습니다.";
  } else if (outcome === "failed") {
    ui.outcomeDetail.textContent = "실행 시도가 실패했으며 프로세스 종료 코드를 확인할 수 없습니다.";
  } else {
    ui.outcomeDetail.textContent = "이 모드에서는 연구 코드를 실행하지 않았습니다.";
  }

  const score = Number.isFinite(assessment.risk_score) ? assessment.risk_score : 0;
  ui.riskDial.style.setProperty("--risk", String(Math.max(0, Math.min(100, score))));
  ui.riskValue.textContent = assessment.risk_score === undefined ? "—" : String(score);
  ui.riskLabel.textContent =
    score >= 70 ? "높음" : score >= 35 ? "주의" : assessment.risk_score === undefined ? "미측정" : "낮음";

  const decisions = report.authorization ? report.authorization.decisions || [] : [];
  ui.allowCount.textContent = String(decisions.filter(function (item) {
    return item.decision === "allow";
  }).length);
  ui.denyCount.textContent = String(decisions.filter(function (item) {
    return item.decision === "deny";
  }).length);
  ui.pendingCount.textContent = String(decisions.filter(function (item) {
    return item.decision === "require_approval";
  }).length);
  ui.elapsed.textContent = Number(elapsedSeconds || 0).toFixed(2) + "초";

  ui.truthBanner.dataset.state = gateState;
  if (gate === "pass") {
    ui.truthTitle.textContent = "보안 게이트 통과";
    ui.truthCopy.textContent = "실행 경로와 독립 증거가 현재 계약을 만족했습니다.";
  } else if (verdict === "unsafe") {
    ui.truthTitle.textContent = "신뢰 가능한 위험 증거가 확인됐습니다";
    ui.truthCopy.textContent = "차단된 행위와 증거 출처를 우선 검토하세요.";
  } else if (gate === "fail") {
    ui.truthTitle.textContent = "보안 검토가 필요합니다";
    ui.truthCopy.textContent = "정책 위반 또는 보류된 권한이 있어 게이트를 통과하지 못했습니다.";
  } else {
    ui.truthTitle.textContent = "아직 안전하다고 결론낼 수 없습니다";
    ui.truthCopy.textContent = outcome === "succeeded"
      ? "실행은 성공했지만 독립 관찰 증거가 부족합니다."
      : "동적 실행 또는 독립 관찰 증거가 부족합니다.";
  }
}

function renderPriority(report) {
  const assessment = report.security_assessment || {};
  let signals = (assessment.reasons || []).slice(0, 6);
  if (signals.length === 0) {
    signals = (report.notes || []).slice(0, 4);
  }
  ui.priorityList.replaceChildren();
  if (signals.length === 0) {
    ui.priorityList.appendChild(emptyPanel("보고할 우선 신호가 없습니다."));
  } else {
    signals.forEach(function (signal, index) {
      const item = element("li");
      const marker = element("span", "signal-marker " + (index === 0 ? "high" : "neutral"));
      marker.setAttribute("aria-hidden", "true");
      const copy = element("div");
      copy.appendChild(element("strong", "", index === 0 ? "핵심 판정 근거" : "추가 확인 사항"));
      copy.appendChild(element("p", "", signal));
      item.append(marker, copy);
      ui.priorityList.appendChild(item);
    });
  }
  ui.signalCount.textContent = String(signals.length) + "건";
}

function evidenceList(items, renderer, emptyMessage, limit) {
  if (!items || items.length === 0) {
    return emptyPanel(emptyMessage);
  }
  const maximum = limit || 200;
  const fragment = document.createDocumentFragment();
  const list = element("ul", "evidence-list");
  items.slice(0, maximum).forEach(function (item, index) {
    list.appendChild(renderer(item, index));
  });
  fragment.appendChild(list);
  if (items.length > maximum) {
    fragment.appendChild(element(
      "p",
      "truncation-note",
      "총 " + String(items.length) + "건 중 앞 " + String(maximum) +
      "건만 표시합니다. 전체 보고서 탭에서 나머지를 확인하세요."
    ));
  }
  return fragment;
}

function renderFindings(report) {
  const assessment = report.security_assessment || {};
  const findings = assessment.static_findings || [];
  ui.findings.replaceChildren(evidenceList(findings, function (finding) {
    const row = element("li", "evidence-item");
    row.appendChild(element("span", "severity " + finding.risk, finding.risk));
    row.appendChild(element("code", "", finding.category + " · " + finding.action + " · " + finding.target));
    row.appendChild(element("p", "", finding.reason));
    return row;
  }, "정적 분석에서 보고된 위험 항목이 없습니다.", 200));
}

function addApproval(requestId) {
  const existing = splitValues(ui.approvals.value);
  if (!existing.includes(requestId)) {
    existing.push(requestId);
    ui.approvals.value = existing.join("\n");
  }
  ui.formStatus.textContent = "승인 ID를 추가했습니다. 새 검사에서만 적용됩니다.";
}

function renderAuthority(report) {
  const decisions = report.authorization ? report.authorization.decisions || [] : [];
  ui.authority.replaceChildren(evidenceList(decisions, function (decision) {
    const request = decision.request || {};
    const row = element("li", "evidence-item");
    row.appendChild(element(
      "span",
      "severity " + decision.decision,
      labels.decision[decision.decision] || decision.decision
    ));
    row.appendChild(element(
      "code",
      "",
      (request.category || "unknown") + " · " +
      (request.action || "unknown") + " · " +
      (request.target || "unknown")
    ));
    const copy = element("div");
    copy.appendChild(element("p", "", decision.reason || "판정 이유 없음"));
    if (decision.decision === "require_approval" && request.request_id) {
      const button = element("button", "approval-button", "이번 검사 승인 목록에 추가");
      button.type = "button";
      button.addEventListener("click", function () { addApproval(request.request_id); });
      copy.appendChild(button);
    }
    row.appendChild(copy);
    return row;
  }, "권한 결정이 아직 없습니다.", 200));
}

function renderRuntime(report) {
  const history = report.execution_history && report.execution_history.length
    ? report.execution_history
    : report.execution ? [report.execution] : [];
  const events = [];
  history.forEach(function (attempt, attemptIndex) {
    (attempt.events || []).forEach(function (event) {
      events.push({
        attempt: attemptIndex + 1,
        attemptStatus: attempt.status,
        event: event
      });
    });
  });
  ui.runtime.replaceChildren(evidenceList(events, function (record) {
    const event = record.event;
    const row = element("li", "evidence-item");
    row.appendChild(element(
      "span",
      "severity " + (event.allowed ? "allow" : "deny"),
      event.allowed ? "허용" : "차단"
    ));
    row.appendChild(element(
      "code",
      "",
      "시도 " + String(record.attempt) + " (" +
      (labels.outcome[record.attemptStatus] || record.attemptStatus) + ") · " +
      (labels.source[event.source] || event.source || "unknown") + " · " +
      event.event_type + " · " + event.action
    ));
    row.appendChild(element("p", "", (event.target || "") + (event.detail ? " — " + event.detail : "")));
    return row;
  }, "이 모드에서는 런타임 이벤트가 없습니다.", 200));
}

function renderReport(result) {
  currentReport = result.report;
  renderSummary(currentReport, result.elapsed_seconds);
  renderPipeline(currentReport);
  renderPriority(currentReport);
  renderFindings(currentReport);
  renderAuthority(currentReport);
  renderRuntime(currentReport);
  ui.rawReport.textContent = JSON.stringify(currentReport, null, 2);
  ui.download.disabled = false;
  ui.formStatus.textContent = "검사가 완료됐습니다. 판정 근거를 확인하세요.";
}

function renderError(error) {
  ui.truthBanner.dataset.state = "danger";
  ui.truthTitle.textContent = "검사를 완료하지 못했습니다";
  ui.truthCopy.textContent = error.message;
  ui.formStatus.textContent = "입력과 Docker 상태를 확인한 뒤 다시 시도하세요.";
  document.querySelectorAll(".pipeline li").forEach(function (item) {
    item.classList.remove("active");
  });
}

async function submitRun(event) {
  event.preventDefault();
  const mode = selectedMode();
  if (mode === "shadow") {
    const confirmed = window.confirm(
      "격리 실행은 Docker에서 연구 코드를 실제로 실행합니다. 계속할까요?"
    );
    if (!confirmed) {
      ui.formStatus.textContent = "격리 실행을 취소했습니다.";
      return;
    }
  }
  const payload = {
    repository: ui.repository.value,
    goal: ui.goal.value,
    output: ui.output.value,
    mode: mode,
    image: ui.image.value,
    approved_request_ids: splitValues(ui.approvals.value),
    network_allowlist: splitValues(ui.network.value),
    confirm_shadow: mode === "shadow"
  };
  try {
    await executePayload(payload);
  } catch (_error) {
    return;
  }
}

async function executePayload(payload) {
  setBusy(true);
  try {
    const result = await api("/api/run", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
    renderReport(result);
    return result;
  } catch (error) {
    const normalized = error instanceof Error ? error : new Error("알 수 없는 오류");
    renderError(normalized);
    throw normalized;
  } finally {
    setBusy(false);
  }
}

function validateToolText(value, name, maximum) {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new Error(name + " 값이 없거나 허용 길이를 초과했습니다.");
  }
  return value.trim();
}

function registerModelTool() {
  const context = document.modelContext;
  if (!context || typeof context.registerTool !== "function") {
    return;
  }
  const lifecycle = new AbortController();
  const registration = context.registerTool(
    {
      name: "run_r_sandbox_static_analysis",
      title: "R-Sandbox 정적 분석 실행",
      description: "사용자가 현재 워크벤치에서 선택한 연구 저장소를 실행하지 않고 분석해 최소 권한과 보안 위험을 표시합니다. 저장소 경로는 이 도구로 변경할 수 없습니다.",
      inputSchema: {
        type: "object",
        properties: {
          goal: {
            type: "string",
            description: "저장소에서 달성하려는 연구 목표",
            minLength: 1,
            maxLength: 16384
          },
          image: {
            type: "string",
            description: "권한 문맥에 결합할 컨테이너 이미지",
            minLength: 1,
            maxLength: 255
          }
        },
        required: ["goal"],
        additionalProperties: false
      },
      annotations: {
        readOnlyHint: true,
        untrustedContentHint: true
      },
      execute: async function (input) {
        if (!input || typeof input !== "object" || Array.isArray(input)) {
          throw new Error("입력은 객체여야 합니다.");
        }
        const keys = Object.keys(input);
        if (keys.some(function (key) {
          return !["goal", "image"].includes(key);
        })) {
          throw new Error("지원하지 않는 입력 필드가 있습니다.");
        }
        const repository = validateToolText(
          ui.repository.value,
          "현재 선택된 repository",
          32768
        );
        const goal = validateToolText(input.goal, "goal", 16384);
        const image = input.image === undefined
          ? ui.image.value
          : validateToolText(input.image, "image", 255);
        ui.goal.value = goal;
        ui.image.value = image;
        const analyzeRadio = document.querySelector('input[name="mode"][value="analyze"]');
        analyzeRadio.checked = true;
        updateMode();
        const result = await executePayload({
          repository: repository,
          goal: goal,
          output: "",
          mode: "analyze",
          image: image,
          approved_request_ids: [],
          network_allowlist: [],
          confirm_shadow: false
        });
        const report = result.report;
        const decisions = report.authorization ? report.authorization.decisions || [] : [];
        return {
          outcome: report.outcome,
          securityGate: report.security_gate_result,
          verdict: report.security_assessment ? report.security_assessment.verdict : "not_evaluated",
          riskScore: report.security_assessment ? report.security_assessment.risk_score : null,
          allowedCapabilities: decisions.filter(function (item) {
            return item.decision === "allow";
          }).length,
          blockedCapabilities: decisions.filter(function (item) {
            return item.decision === "deny";
          }).length,
          pendingCapabilities: decisions.filter(function (item) {
            return item.decision === "require_approval";
          }).length
        };
      }
    },
    {signal: lifecycle.signal}
  );
  Promise.resolve(registration).catch(function () {
    return;
  });
  window.addEventListener("pagehide", function () {
    lifecycle.abort();
  }, {once: true});
}

function downloadReport() {
  if (!currentReport) {
    return;
  }
  const blob = new Blob(
    [JSON.stringify(currentReport, null, 2)],
    {type: "application/json;charset=utf-8"}
  );
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "r-sandbox-report-" + new Date().toISOString().replace(/[:.]/g, "-") + ".json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function setupTabs() {
  const buttons = Array.from(document.querySelectorAll('[role="tab"]'));
  buttons.forEach(function (button, index) {
    button.addEventListener("click", function () {
      buttons.forEach(function (candidate) {
        const selected = candidate === button;
        candidate.setAttribute("aria-selected", selected ? "true" : "false");
        document.getElementById("tab-" + candidate.dataset.tab).hidden = !selected;
      });
    });
    button.addEventListener("keydown", function (event) {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") {
        return;
      }
      event.preventDefault();
      const direction = event.key === "ArrowRight" ? 1 : -1;
      const next = buttons[(index + direction + buttons.length) % buttons.length];
      next.focus();
      next.click();
    });
  });
}

async function bootstrap() {
  sessionToken = safeSessionToken();
  setupTabs();
  document.querySelectorAll('input[name="mode"]').forEach(function (input) {
    input.addEventListener("change", updateMode);
  });
  ui.form.addEventListener("submit", submitRun);
  ui.download.addEventListener("click", downloadReport);
  ui.findings.appendChild(emptyPanel("검사를 시작하면 정적 위험이 여기에 표시됩니다."));
  ui.authority.appendChild(emptyPanel("검사를 시작하면 최소 권한 결정이 여기에 표시됩니다."));
  ui.runtime.appendChild(emptyPanel("격리 실행 후 런타임 이벤트가 여기에 표시됩니다."));
  updateMode();

  if (!sessionToken) {
    ui.dockerPill.dataset.state = "missing";
    ui.dockerLabel.textContent = "세션 인증 필요";
    renderError(new Error("터미널에서 UI를 다시 시작해 인증된 주소로 접속하세요."));
    ui.runButton.disabled = true;
    return;
  }
  try {
    const config = await api("/api/bootstrap");
    ui.repository.value = config.default_repository;
    ui.goal.value = "연구 결과를 안전하게 재현하고 보안 위험을 확인";
    ui.image.value = config.default_image;
    ui.dockerPill.dataset.state = config.docker_cli_available ? "ready" : "missing";
    ui.dockerLabel.textContent = config.docker_cli_available
      ? "Docker CLI 감지됨"
      : "Docker CLI 없음";
    registerModelTool();
  } catch (error) {
    ui.dockerPill.dataset.state = "missing";
    ui.dockerLabel.textContent = "로컬 서버 연결 실패";
    renderError(error instanceof Error ? error : new Error("초기화 실패"));
    ui.runButton.disabled = true;
  }
}

bootstrap();
