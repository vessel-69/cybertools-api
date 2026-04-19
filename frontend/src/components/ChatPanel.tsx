import { useState, useRef, useEffect, KeyboardEvent } from "react";

// ── Types ─────── //

interface Msg {
  id: number;
  role: "user" | "assistant";
  text: string;
  ts: string;
  loading?: boolean;
  model?: string;
}

// ── Models ─────── //

const MODELS = [
  {
    id: "google/gemma-4-26b-a4b-it:free",
    label: "Gemma 4 · 26B",
    tag: "default",
  },
  { id: "google/gemma-3-27b-it:free", label: "Gemma 3 · 27B", tag: "stable" },
  { id: "google/gemma-3-12b-it:free", label: "Gemma 3 · 12B", tag: "fast" },
  { id: "meta-llama/llama-4-scout:free", label: "Llama 4 Scout", tag: "new" },
  {
    id: "meta-llama/llama-3.3-70b-instruct:free",
    label: "Llama 3.3 · 70B",
    tag: "big",
  },
  {
    id: "mistralai/mistral-7b-instruct:free",
    label: "Mistral · 7B",
    tag: "lite",
  },
  { id: "deepseek/deepseek-r1:free", label: "DeepSeek R1", tag: "reason" },
];

// ── API call ─────── //

let _seq = 0;
const uid = () => ++_seq;
const ts = () =>
  new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

async function ask(
  messages: { role: string; content: string }[],
  model: string,
): Promise<string> {
  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages, model }),
    });
    const data = await res.json();
    if (!res.ok) return `⚠ ${data.detail ?? "Request failed"}`;
    return data.reply?.trim() ?? "(empty response)";
  } catch {
    return "⚠ Network error — is the server running on port 6769?";
  }
}

// ── Styles ─────── //

const S = {
  popup: {
    position: "fixed" as const,
    bottom: 84,
    right: 20,
    width: 370,
    height: 560,
    background: "#080b0b",
    border: "1px solid rgba(220,38,38,0.18)",
    borderRadius: 14,
    boxShadow: "0 20px 60px rgba(0,0,0,0.8), 0 0 0 1px rgba(220,38,38,0.06)",
    display: "flex",
    flexDirection: "column" as const,
    zIndex: 9998,
    overflow: "hidden",
    fontFamily: "'JetBrains Mono', monospace",
  },
  header: {
    padding: "11px 14px 10px",
    borderBottom: "1px solid rgba(220,38,38,0.1)",
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    flexShrink: 0,
    background: "#0a0c0c",
  },
  avatar: {
    width: 32,
    height: 32,
    borderRadius: "50%",
    background: "rgba(220,38,38,0.1)",
    border: "1px solid rgba(220,38,38,0.3)",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "0.8rem",
    color: "#e63030",
    flexShrink: 0,
    fontWeight: 700,
  },
  name: {
    fontSize: "0.78rem",
    fontWeight: 700,
    color: "#e8d0d0",
    letterSpacing: 0.3,
  },
  status: {
    display: "flex",
    alignItems: "center",
    gap: 5,
    marginTop: 1,
  },
  dot: {
    width: 5,
    height: 5,
    borderRadius: "50%",
    background: "#4ade80",
    boxShadow: "0 0 5px #4ade80",
  },
  statusTxt: {
    fontSize: "0.58rem",
    color: "#5a3030",
    letterSpacing: 0.5,
  },
  iconBtn: {
    background: "none",
    border: "1px solid rgba(220,38,38,0.12)",
    borderRadius: 5,
    padding: "3px 8px",
    fontSize: "0.58rem",
    letterSpacing: 1,
    textTransform: "uppercase" as const,
    color: "#5a3030",
    cursor: "pointer",
    fontFamily: "'JetBrains Mono', monospace",
    transition: "all 0.12s",
  },
  messages: {
    flex: 1,
    overflowY: "auto" as const,
    padding: "12px 12px 4px",
    display: "flex",
    flexDirection: "column" as const,
    gap: 2,
  },
  suggestions: {
    padding: "6px 12px",
    borderTop: "1px solid rgba(220,38,38,0.06)",
    display: "flex",
    gap: 5,
    flexWrap: "wrap" as const,
    flexShrink: 0,
  },
  suggBtn: {
    padding: "3px 8px",
    borderRadius: 12,
    fontSize: "0.6rem",
    border: "1px solid rgba(220,38,38,0.12)",
    background: "transparent",
    color: "#5a3030",
    cursor: "pointer",
    fontFamily: "'JetBrains Mono', monospace",
    whiteSpace: "nowrap" as const,
    transition: "all 0.12s",
  },
  inputArea: {
    padding: "8px 12px 12px",
    borderTop: "1px solid rgba(220,38,38,0.08)",
    display: "flex",
    gap: 7,
    alignItems: "flex-end",
    flexShrink: 0,
    background: "#080b0b",
  },
  textarea: {
    flex: 1,
    background: "#0f1212",
    border: "1px solid rgba(220,38,38,0.12)",
    borderRadius: 8,
    padding: "7px 10px",
    color: "#d0c8c8",
    fontFamily: "'JetBrains Mono', monospace",
    fontSize: "0.74rem",
    outline: "none",
    resize: "none" as const,
    caretColor: "#e63030",
    lineHeight: 1.55,
    transition: "border-color 0.15s",
  },
  sendBtn: (active: boolean) => ({
    width: 34,
    height: 34,
    borderRadius: 8,
    flexShrink: 0,
    background: active ? "#e63030" : "#0f1212",
    border: `1px solid ${active ? "#e63030" : "rgba(220,38,38,0.15)"}`,
    color: active ? "#fff" : "#3a1a1a",
    cursor: active ? "pointer" : "not-allowed",
    fontSize: "0.85rem",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    transition: "all 0.15s",
  }),
  fab: (open: boolean) => ({
    position: "fixed" as const,
    bottom: 20,
    right: 20,
    width: 50,
    height: 50,
    borderRadius: "50%",
    background: open ? "#0f1212" : "#e63030",
    border: `1.5px solid ${open ? "rgba(220,38,38,0.4)" : "#e63030"}`,
    boxShadow: `0 4px 18px rgba(220,38,38,${open ? 0.15 : 0.4})`,
    cursor: "pointer",
    zIndex: 9999,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: open ? "1rem" : "1.2rem",
    color: open ? "#e63030" : "#fff",
    transition: "all 0.2s cubic-bezier(.34,1.56,.64,1)",
    transform: open ? "rotate(45deg)" : "none",
  }),
};

// ── Bubble ─────── //

function UserMsg({ msg }: { msg: Msg }) {
  return (
    <div
      style={{ display: "flex", justifyContent: "flex-end", marginBottom: 10 }}
    >
      <div style={{ maxWidth: "82%" }}>
        <div
          style={{
            background: "rgba(220,38,38,0.12)",
            border: "1px solid rgba(220,38,38,0.22)",
            borderRadius: "12px 12px 2px 12px",
            padding: "8px 11px",
            fontSize: "0.76rem",
            lineHeight: 1.55,
            color: "#e8d8d8",
            wordBreak: "break-word",
          }}
        >
          {msg.text}
        </div>
        <div
          style={{
            fontSize: "0.56rem",
            color: "#3a1a1a",
            textAlign: "right",
            marginTop: 2,
          }}
        >
          {msg.ts}
        </div>
      </div>
    </div>
  );
}

function BotMsg({ msg }: { msg: Msg }) {
  return (
    <div
      style={{
        display: "flex",
        gap: 8,
        marginBottom: 10,
        alignItems: "flex-start",
      }}
    >
      <div style={S.avatar}>⌖</div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontSize: "0.56rem",
            color: "#5a2a2a",
            letterSpacing: 1,
            textTransform: "uppercase",
            marginBottom: 3,
          }}
        >
          CyberTools AI{" "}
          {msg.model ? `· ${msg.model.split("/").pop()?.split(":")[0]}` : ""}
        </div>
        {msg.loading ? (
          <div
            style={{
              background: "#0f1212",
              border: "1px solid rgba(220,38,38,0.1)",
              borderRadius: "2px 12px 12px 12px",
              padding: "9px 13px",
              display: "flex",
              gap: 4,
              alignItems: "center",
            }}
          >
            {[0, 1, 2].map((i) => (
              <span
                key={i}
                style={{
                  width: 5,
                  height: 5,
                  borderRadius: "50%",
                  background: "#e63030",
                  display: "inline-block",
                  animation: `dots 1.1s ${i * 0.16}s ease-in-out infinite`,
                }}
              />
            ))}
          </div>
        ) : (
          <div
            style={{
              background: "#0f1212",
              border: "1px solid rgba(220,38,38,0.1)",
              borderRadius: "2px 12px 12px 12px",
              padding: "9px 11px",
              fontSize: "0.75rem",
              lineHeight: 1.65,
              color: "#c8c0c0",
              wordBreak: "break-word",
              whiteSpace: "pre-wrap",
            }}
          >
            {msg.text}
          </div>
        )}
        {!msg.loading && (
          <div style={{ fontSize: "0.56rem", color: "#3a1a1a", marginTop: 2 }}>
            {msg.ts}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main ─────── //

const HINTS = [
  "How do I find XSS?",
  "What is IDOR?",
  "Test for SQLi?",
  "Find subdomains?",
  "What is SSRF?",
  "/bb-scan usage?",
];

export default function ChatPanel() {
  const [open, setOpen] = useState(false);
  const [model, setModel] = useState(MODELS[0].id);
  const [msgs, setMsgs] = useState<Msg[]>([
    {
      id: uid(),
      role: "assistant",
      ts: ts(),
      text: "Red team assistant ready.\nAsk me about bug bounty, web security, or any CyberTools feature.",
    },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [modelOpen, setModelOpen] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const hist = useRef<{ role: string; content: string }[]>([]);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgs]);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 60);
  }, [open]);

  async function send(text?: string) {
    const q = (text ?? input).trim();
    if (!q || busy) return;
    setInput("");
    setBusy(true);

    const uid1 = uid();
    const uid2 = uid();
    hist.current.push({ role: "user", content: q });
    setMsgs((p) => [
      ...p,
      { id: uid1, role: "user", text: q, ts: ts() },
      { id: uid2, role: "assistant", text: "", ts: ts(), loading: true },
    ]);

    const reply = await ask(hist.current, model);
    hist.current.push({ role: "assistant", content: reply });

    setMsgs((p) =>
      p.map((m) =>
        m.id === uid2 ? { ...m, text: reply, loading: false, model } : m,
      ),
    );
    setBusy(false);
  }

  function clear() {
    hist.current = [];
    setMsgs([
      { id: uid(), role: "assistant", ts: ts(), text: "Chat cleared." },
    ]);
  }

  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  }

  const activeModel = MODELS.find((m) => m.id === model) ?? MODELS[0];

  return (
    <>
      {/* ── Popup ── */}
      {open && (
        <div style={S.popup}>
          {/* Header */}
          <div style={S.header}>
            <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
              <div style={S.avatar}>⌖</div>
              <div>
                <div style={S.name}>CyberTools AI</div>
                <div style={S.status}>
                  <span style={S.dot} />
                  <span style={S.statusTxt}>
                    {busy ? "thinking..." : "online · red team assistant"}
                  </span>
                </div>
              </div>
            </div>

            <div
              style={{
                display: "flex",
                gap: 5,
                alignItems: "center",
                position: "relative",
              }}
            >
              {/* Model picker */}
              <button
                onClick={() => setModelOpen((o) => !o)}
                style={{ ...S.iconBtn, fontSize: "0.58rem", paddingRight: 10 }}
                title="Switch model"
              >
                {activeModel.label}
                <span style={{ marginLeft: 4, opacity: 0.5 }}>▾</span>
              </button>

              {modelOpen && (
                <div
                  style={{
                    position: "absolute",
                    top: "110%",
                    right: 0,
                    background: "#0a0c0c",
                    border: "1px solid rgba(220,38,38,0.2)",
                    borderRadius: 8,
                    zIndex: 10,
                    minWidth: 190,
                    overflow: "hidden",
                    boxShadow: "0 8px 24px rgba(0,0,0,0.6)",
                  }}
                >
                  {MODELS.map((m) => (
                    <button
                      key={m.id}
                      onClick={() => {
                        setModel(m.id);
                        setModelOpen(false);
                      }}
                      style={{
                        width: "100%",
                        textAlign: "left",
                        padding: "7px 12px",
                        background:
                          m.id === model
                            ? "rgba(220,38,38,0.1)"
                            : "transparent",
                        border: "none",
                        borderBottom: "1px solid rgba(220,38,38,0.06)",
                        color: m.id === model ? "#e63030" : "#7a5050",
                        fontSize: "0.68rem",
                        cursor: "pointer",
                        fontFamily: "'JetBrains Mono', monospace",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        gap: 8,
                      }}
                    >
                      <span>{m.label}</span>
                      <span
                        style={{
                          fontSize: "0.55rem",
                          opacity: 0.6,
                          background: "rgba(220,38,38,0.12)",
                          padding: "1px 5px",
                          borderRadius: 3,
                          color: "#e63030",
                        }}
                      >
                        {m.tag}
                      </span>
                    </button>
                  ))}
                </div>
              )}

              <button
                onClick={clear}
                style={S.iconBtn}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = "#e63030";
                  e.currentTarget.style.borderColor = "rgba(220,38,38,0.4)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = "#5a3030";
                  e.currentTarget.style.borderColor = "rgba(220,38,38,0.12)";
                }}
              >
                CLR
              </button>

              <button
                onClick={() => setOpen(false)}
                style={{ ...S.iconBtn, padding: "3px 7px", fontSize: "0.7rem" }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = "#e63030";
                  e.currentTarget.style.borderColor = "rgba(220,38,38,0.4)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = "#5a3030";
                  e.currentTarget.style.borderColor = "rgba(220,38,38,0.12)";
                }}
              >
                ✕
              </button>
            </div>
          </div>

          {/* Messages */}
          <div style={S.messages} onClick={() => setModelOpen(false)}>
            {msgs.map((m) =>
              m.role === "user" ? (
                <UserMsg key={m.id} msg={m} />
              ) : (
                <BotMsg key={m.id} msg={m} />
              ),
            )}
            <div ref={scrollRef} />
          </div>

          {/* Quick hints */}
          <div style={S.suggestions}>
            {HINTS.map((h) => (
              <button
                key={h}
                onClick={() => send(h)}
                style={S.suggBtn}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = "#e63030";
                  e.currentTarget.style.borderColor = "rgba(220,38,38,0.35)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = "#5a3030";
                  e.currentTarget.style.borderColor = "rgba(220,38,38,0.12)";
                }}
              >
                {h}
              </button>
            ))}
          </div>

          {/* Input */}
          <div style={S.inputArea}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKey}
              placeholder="Ask about exploits, endpoints, payloads…  (↵ send)"
              rows={2}
              style={S.textarea}
              onFocus={(e) => {
                e.target.style.borderColor = "rgba(220,38,38,0.35)";
              }}
              onBlur={(e) => {
                e.target.style.borderColor = "rgba(220,38,38,0.12)";
              }}
            />
            <button
              onClick={() => send()}
              disabled={busy || !input.trim()}
              style={S.sendBtn(!!input.trim() && !busy)}
            >
              ▸
            </button>
          </div>
        </div>
      )}

      {/* ── FAB ── */}
      <div
        onClick={() => setOpen((o) => !o)}
        style={S.fab(open)}
        title="CyberTools AI"
        role="button"
        tabIndex={0}
      >
        {open ? "+" : "⌖"}
      </div>

      <style>{`
        @keyframes dots {
          0%,60%,100% { opacity:.15; transform:scale(.7); }
          30%          { opacity:1;   transform:scale(1);  }
        }
        @keyframes chatSlide {
          from { opacity:0; transform:translateY(10px) scale(.97); }
          to   { opacity:1; transform:translateY(0) scale(1); }
        }
      `}</style>
    </>
  );
}
