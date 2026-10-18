# 과제 8 — 내 소개 페이지에 패스키 달기

> 공개 자기소개 페이지는 그대로 보여주고, 별도 PRIVATE 기록실만 WebAuthn 패스키로 보호한 실습 프로젝트입니다. 비밀번호와 실제 개인정보는 사용하지 않습니다.

## 제출 주소

- **공개 결과물:** https://jm-portfolio-passkey.vercel.app/
- **소스 코드:** https://github.com/jennajiminkim/jm-portfolio-passkey
- **인증 구현 설명서 6항목 및 실제 보안 검사 기록:** [TASK8-README.md](./TASK8-README.md)

## 확인 방법 4줄

1. **어디로 가나요:** 배포 주소를 열고 상단 PUBLIC / PRIVATE 탭을 확인합니다.
2. **세 단계 안에 무엇을 하나요:** PUBLIC 소개 확인 → PRIVATE 탭 이동 → 패스키 인증 후 자기 계정의 가상 기록 3건 확인(심사자는 인증할 필요 없음).
3. **통과 모습:** 로그인 없이 기존 소개가 보이고, 패스키 인증 뒤 자신의 기록 3건만 반환되며 두 개의 키를 관리할 수 있습니다.
4. **차단 모습:** 비인증 private 요청은 HTTP 401, 다른 계정 요청은 403, 사용한 Challenge 재사용은 401, 마지막 키 삭제는 409입니다.

## 인증 구현 위치

| 기능 | 브라우저 | 서버 |
| --- | --- | --- |
| 패스키 등록 | `index.html`의 `register()` | `api/auth.js`: `register-options`, `register-verify` |
| 패스키 로그인 | `index.html`의 `signIn()` | `login-options`, `login-verify` |
| 로그아웃 | `index.html`의 로그아웃 이벤트 | `logout` |
| 비공개 자료 조회 | `index.html`의 `refresh()` | `private`, `account(req)` |
| 계정별 접근 차단 | `isolatedProbe()` 검사 UI | `private-target`, `private` |
| 원본 공개 소개 | `portfolio.html` | 인증 없이 공개 |

## 실측 보안 검사 요약

사용자 실행 결과: TEST-A/B 각 계정 자료 3 → 3 유지, 양방향 다른 계정 접근 HTTP 403, 사용한 로그인 질문 재전송 HTTP 401, 삭제된 Apple 패스키 HTTP 403, 마지막 키 삭제 HTTP 409, 로그아웃 이전 세션 재사용 수정 후 HTTP 401, 변조 서명 HTTP 403, 등록/로그인 질문 각 2회 모두 서로 다름, 무로그인 PUBLIC 화면과 GitHub 소스 시크릿 창 접근 확인. 서버 공개키 접두 확인 및 패스키 등록 중단 후 키 1 → 1 유지도 수행했습니다.

이 저장소의 비공개 기록은 **실제 개인 데이터가 아닌 가상 샘플 3건**입니다. 서명, 개인키, 세션 쿠키, 인증 질문 원문, 실제 개인정보는 이 문서에 포함하지 않았습니다.

**여섯 항목 설명서, 시험별 요청/응답 결과, 실패 후 수정 기록, 아직 못 막은 문제, AI와 직접 판단 3줄은 [TASK8-README.md](./TASK8-README.md)에 정리되어 있습니다.**

## 알려진 한계

인증 질문 삭제와 상태 갱신은 Blob 기반 비원자적 작업이므로 동시 요청 경합을 완전히 해결하지 못했습니다. 가입 남용에 대한 rate limiting과 모든 키를 잃었을 때의 복구 수단이 없습니다. 마지막 패스키 삭제는 서버에서 거절합니다. 제출용 시크릿 창/검사 화면의 일부는 대화 첨부 증거로 보관되어 있으며 저장소에 업로드하지 않았습니다.
