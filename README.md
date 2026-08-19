# SentinelBox

> **Deterministic Agentic Sandboxing & Local-First State Verification Engine**

SentinelBox provides an atomic transaction layer for autonomous AI coding agents operating on local software repositories. It guarantees that live source code is never mutated until commands, filesystem mutations, and test suites are verified deterministically.

---

## Architectural Workflow

```text
AI CODING AGENT
       │
       ▼
+───────────────────────────+
│   SentinelBox Agent API   │
+─────────────┬─────────────+
              │
              ▼
+───────────────────────────+
│   Command Guard / Policy  │ ── [DENY / TRAVERSAL] ──► ABORT & AUDIT
+─────────────┬─────────────+
              │ [ALLOW]
              ▼
+───────────────────────────+
│   Transactional Workspace │
+─────────────┬─────────────+
              │
              ▼
+───────────────────────────+
│    Process Tree Executor  │ ── [TIMEOUT / OVERFLOW] ──► TERMINATE & ROLLBACK
+─────────────┬─────────────+
              │
              ▼
+───────────────────────────+
│    Verification Engine    │
│  (compile, test, lint)    │
+─────────────┬─────────────+
              │
        ┌─────┴─────┐
      FAIL        PASS
        │           │
        ▼           ▼
    ROLLBACK   ATOMIC COMMIT (with External Conflict Check)
        │           │
        ▼           ▼
     DISCARD   LIVE WORKSPACE UPDATED