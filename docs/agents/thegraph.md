# thegraph build

## What this project is

순수 Rust SSH 클라이언트·서버 라이브러리(sans-IO 상태기계 코어 + 얇은 I/O 어댑터). 존재 이유는 acwbroker(Go → Rust 이전)가 채널·전역 요청과 채널 열기를 원시 그대로(봉투째) 중계하는 것.

## References

| Source | Informs | Reached by | Binding |
|---|---|---|---|
| RFC 4251–4254, 8308, 8332, 9142 | how it works | rfc-editor.org 원문 — raw | binding |
| OpenSSH `PROTOCOL`·`PROTOCOL.*` (strict-kex 포함) | how it works | openssh-portable 소스 트리 — raw | binding |
| x/crypto/ssh | how it works (acwbroker 현재 동작) | 소스 트리 — raw | binding: acwbroker가 관측할 수 있는 동작에 한함 |
| acwbroker `blackbox/` | 완료 판정 | acwbroker 저장소 — raw | binding: Go 기준과 상류 payload 바이트가 같아야 함. tail(stderr·exit-status) 판정은 OpenSSH 클라로 (plink 0.83은 직결에서도 잃음) |
| IronRDP · sspi | 의존성 버전 제약 | 각 Cargo.toml / Cargo.lock — raw | binding |
| justrdp | how it works · where files go | 소스 트리 — raw | example |
| russh | how it works (구조) | 소스 트리 — raw | example |
| puressh | how it works (원시 요청 보존) | 소스 트리 — raw | example |
| Warpgate | 의존성 정렬 선례 | 소스 트리(Cargo.toml) — raw | example |
