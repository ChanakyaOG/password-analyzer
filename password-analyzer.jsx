import { useState, useCallback, useEffect } from "react";

// ─── Crypto helpers ───────────────────────────────────────────────────────────
async function sha256(str) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(str)
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Check HaveIBeenPwned via k-Anonymity (first 5 chars of hash)
async function checkPwned(password) {
  try {
    const hash = (await sha256(password)).toUpperCase();
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await fetch(
      `https://api.pwnedpasswords.com/range/${prefix}`
    );
    if (!res.ok) return null;
    const text = await res.text();
    const lines = text.split("\r\n");
    for (const line of lines) {
      const [s, count] = line.split(":");
      if (s === suffix) return parseInt(count, 10);
    }
    return 0;
  } catch {
    return null;
  }
}

// ─── Strength engine ──────────────────────────────────────────────────────────
function analyze(password) {
  const checks = {
    length8: password.length >= 8,
    length12: password.length >= 12,
    length16: password.length >= 16,
    hasLower: /[a-z]/.test(password),
    hasUpper: /[A-Z]/.test(password),
    hasDigit: /\d/.test(password),
    hasSymbol: /[^a-zA-Z0-9]/.test(password),
    noRepeats: !/(.)\1{2,}/.test(password),
    noSequential: !/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(password),
    noCommon: !["password","123456","qwerty","letmein","admin","welcome","monkey","dragon","master","sunshine"].some(c => password.toLowerCase().includes(c)),
  };

  // Entropy estimate
  let pool = 0;
  if (checks.hasLower) pool += 26;
  if (checks.hasUpper) pool += 26;
  if (checks.hasDigit) pool += 10;
  if (checks.hasSymbol) pool += 32;
  const entropy = pool > 0 ? Math.floor(password.length * Math.log2(pool)) : 0;

  // Score 0-100
  let score = 0;
  if (checks.length8) score += 10;
  if (checks.length12) score += 15;
  if (checks.length16) score += 10;
  if (checks.hasLower) score += 10;
  if (checks.hasUpper) score += 10;
  if (checks.hasDigit) score += 10;
  if (checks.hasSymbol) score += 15;
  if (checks.noRepeats) score += 5;
  if (checks.noSequential) score += 5;
  if (checks.noCommon) score += 10;
  score = Math.min(100, score);

  const level =
    score < 25 ? "Critical"
    : score < 50 ? "Weak"
    : score < 70 ? "Fair"
    : score < 85 ? "Strong"
    : "Excellent";

  return { checks, score, entropy, level };
}

function suggest(password, checks) {
  const tips = [];
  if (!checks.length12) tips.push("Use at least 12 characters");
  if (!checks.hasUpper) tips.push("Add uppercase letters (A–Z)");
  if (!checks.hasLower) tips.push("Add lowercase letters (a–z)");
  if (!checks.hasDigit) tips.push("Include numbers (0–9)");
  if (!checks.hasSymbol) tips.push("Add symbols (!@#$%^&*)");
  if (!checks.noRepeats) tips.push("Avoid repeated characters (aaa, 111)");
  if (!checks.noSequential) tips.push("Avoid sequential patterns (abc, 123)");
  if (!checks.noCommon) tips.push("Remove common words or patterns");
  return tips;
}

// Generate a strong random password
function generatePassword(length = 16) {
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const digits = "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?";
  const all = lower + upper + digits + symbols;
  const arr = new Uint32Array(length);
  crypto.getRandomValues(arr);
  let pwd = [
    lower[arr[0] % lower.length],
    upper[arr[1] % upper.length],
    digits[arr[2] % digits.length],
    symbols[arr[3] % symbols.length],
    ...Array.from({ length: length - 4 }, (_, i) => all[arr[i + 4] % all.length]),
  ];
  // Shuffle
  for (let i = pwd.length - 1; i > 0; i--) {
    const j = arr[i] % (i + 1);
    [pwd[i], pwd[j]] = [pwd[j], pwd[i]];
  }
  return pwd.join("");
}

// ─── History (in-memory, no localStorage) ────────────────────────────────────
const passwordHistory = [];

function addToHistory(password, hash) {
  if (!passwordHistory.find((e) => e.hash === hash)) {
    passwordHistory.unshift({ hash, snippet: password.slice(0, 2) + "•".repeat(Math.max(0, password.length - 4)) + password.slice(-2), time: Date.now() });
    if (passwordHistory.length > 10) passwordHistory.pop();
  }
}

function wasReused(hash) {
  return passwordHistory.filter((e) => e.hash === hash).length > 1;
}

// ─── UI ──────────────────────────────────────────────────────────────────────
const LEVEL_CONFIG = {
  Critical: { color: "#ff3b3b", bg: "#2a0a0a", bar: "#ff3b3b", icon: "✕" },
  Weak:     { color: "#ff8c00", bg: "#1f1400", bar: "#ff8c00", icon: "▲" },
  Fair:     { color: "#f5d000", bg: "#1f1b00", bar: "#f5d000", icon: "◐" },
  Strong:   { color: "#39d353", bg: "#001a08", bar: "#39d353", icon: "✓" },
  Excellent:{ color: "#00e5ff", bg: "#001a1f", bar: "#00e5ff", icon: "★" },
};

export default function PasswordAnalyzer() {
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [result, setResult] = useState(null);
  const [tips, setTips] = useState([]);
  const [pwnedCount, setPwnedCount] = useState(null);
  const [pwnedLoading, setPwnedLoading] = useState(false);
  const [generated, setGenerated] = useState("");
  const [copiedGen, setCopiedGen] = useState(false);
  const [copiedPwd, setCopiedPwd] = useState(false);
  const [history, setHistory] = useState([]);
  const [reused, setReused] = useState(false);

  useEffect(() => {
    if (!password) {
      setResult(null);
      setTips([]);
      setPwnedCount(null);
      setReused(false);
      return;
    }
    const r = analyze(password);
    setResult(r);
    setTips(suggest(password, r.checks));

    // Hash and check reuse
    sha256(password).then((hash) => {
      addToHistory(password, hash);
      setHistory([...passwordHistory]);
      setReused(wasReused(hash));
    });

    // Debounced pwned check
    setPwnedCount(null);
    setPwnedLoading(true);
    const t = setTimeout(() => {
      checkPwned(password).then((c) => {
        setPwnedCount(c);
        setPwnedLoading(false);
      });
    }, 600);
    return () => clearTimeout(t);
  }, [password]);

  const handleGenerate = () => {
    const pwd = generatePassword(18);
    setGenerated(pwd);
    setCopiedGen(false);
  };

  const copyText = (text, which) => {
    navigator.clipboard.writeText(text).then(() => {
      if (which === "gen") { setCopiedGen(true); setTimeout(() => setCopiedGen(false), 2000); }
      else { setCopiedPwd(true); setTimeout(() => setCopiedPwd(false), 2000); }
    });
  };

  const cfg = result ? LEVEL_CONFIG[result.level] : null;

  return (
    <div style={{
      minHeight: "100vh",
      background: "linear-gradient(135deg, #0a0a0f 0%, #0d0d1a 50%, #0a0f0a 100%)",
      fontFamily: "'Courier New', Courier, monospace",
      color: "#c8d6c8",
      padding: "32px 16px",
      boxSizing: "border-box",
    }}>
      {/* Header */}
      <div style={{ maxWidth: 560, margin: "0 auto 32px" }}>
        <div style={{ fontSize: 11, letterSpacing: 6, color: "#3a6b3a", marginBottom: 8, textTransform: "uppercase" }}>
          Security Tool
        </div>
        <h1 style={{
          fontSize: "clamp(28px, 6vw, 48px)",
          fontWeight: 900,
          margin: 0,
          lineHeight: 1,
          color: "#e8f5e8",
          letterSpacing: -1,
        }}>
          PASSWORD<br />
          <span style={{ color: "#39d353", fontStyle: "italic" }}>STRENGTH</span>{" "}
          <span style={{ color: "#444" }}>ANALYZER</span>
        </h1>
        <p style={{ fontSize: 13, color: "#4a7a4a", marginTop: 12, marginBottom: 0 }}>
          Real-time analysis · Entropy scoring · Breach detection
        </p>
      </div>

      <div style={{ maxWidth: 560, margin: "0 auto" }}>
        {/* Input */}
        <div style={{
          background: "#0f1a0f",
          border: "1px solid #1e3a1e",
          borderRadius: 4,
          padding: "20px 20px 16px",
          marginBottom: 16,
          position: "relative",
        }}>
          <label style={{ fontSize: 10, letterSpacing: 4, color: "#3a6b3a", display: "block", marginBottom: 10 }}>
            ENTER PASSWORD
          </label>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <input
              type={show ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Type or paste a password…"
              style={{
                flex: 1,
                background: "transparent",
                border: "none",
                outline: "none",
                fontSize: 20,
                color: cfg ? cfg.color : "#e8f5e8",
                fontFamily: "inherit",
                letterSpacing: show ? 1 : 4,
                caretColor: "#39d353",
              }}
            />
            <button
              onClick={() => setShow((s) => !s)}
              style={{ background: "none", border: "none", cursor: "pointer", color: "#3a6b3a", fontSize: 14, padding: 4 }}
              title={show ? "Hide" : "Show"}
            >
              {show ? "HIDE" : "SHOW"}
            </button>
            {password && (
              <button
                onClick={() => copyText(password, "pwd")}
                style={{ background: "none", border: "none", cursor: "pointer", color: "#3a6b3a", fontSize: 12, padding: 4 }}
              >
                {copiedPwd ? "✓" : "COPY"}
              </button>
            )}
          </div>
          {password && (
            <div style={{ marginTop: 12, height: 3, background: "#1e3a1e", borderRadius: 2, overflow: "hidden" }}>
              <div style={{
                height: "100%",
                width: `${result?.score ?? 0}%`,
                background: cfg?.bar ?? "#39d353",
                borderRadius: 2,
                transition: "width 0.4s ease, background 0.3s ease",
                boxShadow: `0 0 10px ${cfg?.color ?? "#39d353"}66`,
              }} />
            </div>
          )}
        </div>

        {/* Result panel */}
        {result && cfg && (
          <div style={{
            background: cfg.bg,
            border: `1px solid ${cfg.color}33`,
            borderRadius: 4,
            padding: "20px",
            marginBottom: 16,
            transition: "all 0.3s ease",
          }}>
            {/* Level + score */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span style={{ fontSize: 22, color: cfg.color }}>{cfg.icon}</span>
                <span style={{ fontSize: 22, fontWeight: 900, color: cfg.color, letterSpacing: 2 }}>
                  {result.level.toUpperCase()}
                </span>
              </div>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: 28, fontWeight: 900, color: cfg.color }}>{result.score}</div>
                <div style={{ fontSize: 10, color: "#3a6b3a", letterSpacing: 2 }}>/ 100</div>
              </div>
            </div>

            {/* Stats grid */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 8, marginBottom: 16 }}>
              {[
                { label: "LENGTH", value: password.length },
                { label: "ENTROPY", value: `${result.entropy} bits` },
                { label: "BREACH", value: pwnedLoading ? "…" : pwnedCount === null ? "N/A" : pwnedCount === 0 ? "SAFE" : `${pwnedCount.toLocaleString()}×` },
              ].map(({ label, value }) => (
                <div key={label} style={{
                  background: "#0a0f0a",
                  border: "1px solid #1e3a1e",
                  borderRadius: 3,
                  padding: "10px 12px",
                }}>
                  <div style={{ fontSize: 9, letterSpacing: 3, color: "#3a6b3a", marginBottom: 4 }}>{label}</div>
                  <div style={{ fontSize: 16, fontWeight: 700, color: label === "BREACH" && pwnedCount > 0 ? "#ff3b3b" : "#e8f5e8" }}>
                    {value}
                  </div>
                </div>
              ))}
            </div>

            {/* Checks */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 4 }}>
              {[
                ["12+ chars", result.checks.length12],
                ["Uppercase", result.checks.hasUpper],
                ["Lowercase", result.checks.hasLower],
                ["Numbers", result.checks.hasDigit],
                ["Symbols", result.checks.hasSymbol],
                ["No repeats", result.checks.noRepeats],
                ["No sequences", result.checks.noSequential],
                ["Not common", result.checks.noCommon],
              ].map(([label, ok]) => (
                <div key={label} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
                  <span style={{ color: ok ? "#39d353" : "#3a2a2a", fontSize: 14, minWidth: 16 }}>
                    {ok ? "✓" : "✕"}
                  </span>
                  <span style={{ color: ok ? "#7abf7a" : "#4a3a3a" }}>{label}</span>
                </div>
              ))}
            </div>

            {/* Reuse warning */}
            {reused && (
              <div style={{
                marginTop: 12,
                padding: "8px 12px",
                background: "#1f0a00",
                border: "1px solid #ff8c0055",
                borderRadius: 3,
                fontSize: 12,
                color: "#ff8c00",
              }}>
                ⚠ This password was used before in this session
              </div>
            )}

            {/* Breach warning */}
            {pwnedCount > 0 && (
              <div style={{
                marginTop: 8,
                padding: "8px 12px",
                background: "#1f0000",
                border: "1px solid #ff3b3b55",
                borderRadius: 3,
                fontSize: 12,
                color: "#ff3b3b",
              }}>
                🔴 Found in {pwnedCount.toLocaleString()} data breaches — do not use this password
              </div>
            )}
          </div>
        )}

        {/* Suggestions */}
        {tips.length > 0 && (
          <div style={{
            background: "#0f0f1a",
            border: "1px solid #1e1e3a",
            borderRadius: 4,
            padding: "16px 20px",
            marginBottom: 16,
          }}>
            <div style={{ fontSize: 10, letterSpacing: 4, color: "#3a3a6b", marginBottom: 12 }}>HOW TO IMPROVE</div>
            {tips.map((tip, i) => (
              <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: 10, marginBottom: 6, fontSize: 13, color: "#9a9abf" }}>
                <span style={{ color: "#3a3a6b", minWidth: 16, marginTop: 1 }}>→</span>
                {tip}
              </div>
            ))}
          </div>
        )}

        {/* Password generator */}
        <div style={{
          background: "#0a0f14",
          border: "1px solid #1e2a3a",
          borderRadius: 4,
          padding: "16px 20px",
          marginBottom: 16,
        }}>
          <div style={{ fontSize: 10, letterSpacing: 4, color: "#2a5a7a", marginBottom: 12 }}>GENERATE STRONG PASSWORD</div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <button
              onClick={handleGenerate}
              style={{
                background: "#0d2030",
                border: "1px solid #1e4060",
                borderRadius: 3,
                color: "#5ab0e0",
                fontFamily: "inherit",
                fontSize: 11,
                letterSpacing: 2,
                padding: "8px 16px",
                cursor: "pointer",
                transition: "all 0.2s",
              }}
              onMouseEnter={(e) => e.target.style.background = "#1e4060"}
              onMouseLeave={(e) => e.target.style.background = "#0d2030"}
            >
              GENERATE
            </button>
            {generated && (
              <>
                <code style={{
                  flex: 1,
                  fontSize: 13,
                  color: "#00e5ff",
                  background: "#050d14",
                  border: "1px solid #0a2030",
                  borderRadius: 3,
                  padding: "6px 10px",
                  wordBreak: "break-all",
                  minWidth: 0,
                }}>
                  {generated}
                </code>
                <button
                  onClick={() => copyText(generated, "gen")}
                  style={{
                    background: "none",
                    border: "none",
                    cursor: "pointer",
                    color: copiedGen ? "#39d353" : "#2a5a7a",
                    fontFamily: "inherit",
                    fontSize: 11,
                    letterSpacing: 2,
                    padding: "6px",
                    whiteSpace: "nowrap",
                  }}
                >
                  {copiedGen ? "COPIED!" : "COPY"}
                </button>
                <button
                  onClick={() => setPassword(generated)}
                  style={{
                    background: "none",
                    border: "1px solid #1e3a1e",
                    borderRadius: 3,
                    cursor: "pointer",
                    color: "#39d353",
                    fontFamily: "inherit",
                    fontSize: 11,
                    letterSpacing: 2,
                    padding: "6px 10px",
                    whiteSpace: "nowrap",
                  }}
                >
                  TEST IT
                </button>
              </>
            )}
          </div>
        </div>

        {/* History */}
        {history.length > 1 && (
          <div style={{
            background: "#0a0a0f",
            border: "1px solid #1a1a2a",
            borderRadius: 4,
            padding: "14px 20px",
          }}>
            <div style={{ fontSize: 10, letterSpacing: 4, color: "#2a2a4a", marginBottom: 10 }}>
              SESSION HISTORY ({history.length})
            </div>
            {history.slice(0, 5).map((entry, i) => (
              <div key={i} style={{
                display: "flex",
                justifyContent: "space-between",
                fontSize: 12,
                color: "#3a3a5a",
                padding: "4px 0",
                borderBottom: i < Math.min(history.length, 5) - 1 ? "1px solid #1a1a2a" : "none",
              }}>
                <code style={{ color: "#4a4a7a" }}>{entry.snippet}</code>
                <span style={{ fontSize: 10, color: "#2a2a3a" }}>
                  {new Date(entry.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* Footer note */}
        <div style={{ marginTop: 20, fontSize: 10, color: "#2a3a2a", textAlign: "center", lineHeight: 1.6 }}>
          Breach check via HaveIBeenPwned k-Anonymity API · Passwords never leave your browser
        </div>
      </div>
    </div>
  );
}
