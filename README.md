# Ubuntu Secure Patch Script (USPS)

**OS Secure Patch Script(OSPS)**는 Ubuntu 기반 서버의 보안 패치 및 시스템 보안 설정을 쉽고 빠르게 자동화하는 Bash 스크립트입니다. 

## 주요 특징
- 시스템 패키지 업데이트 및 업그레이드
- 자동 업데이트 설정
- UFW 방화벽 정책 및 SSH 허용 IP/포트 설정
- 미사용 파일시스템 비활성화
- 강력한 비밀번호 정책 적용
- 루트 로그인 비활성화
- SSH 보안 설정(포트, 인증, 시도 횟수 등)
- 감사 로그(auditd) 및 로그 회전 설정
- 사용자 권한 및 디렉토리 보안 강화
- 시스템 로그 설정
- 루트킷 검사(rkhunter) 및 Fail2Ban 설정
- whiptail 기반 GUI 메뉴 제공(선택적 패치, 설정파일 편집 등)

## 사용법
1. **스크립트 실행**
   ```bash
   sudo bash OSPS_ubuntu.sh
   ```
2. **메뉴에서 원하는 보안 패치 항목을 선택하여 실행**
3. **설정 수정 메뉴에서 osps.conf 파일을 vi로 편집 가능**

## 설정 파일(osps.conf)
- 모든 주요 보안 정책 및 환경설정은 `osps.conf` 파일에서 관리합니다.
- 예시:
  ```ini
  # 시스템 기본 설정
  TIMEZONE=Asia/Seoul
  # SSH 설정
  SSH_PORT=22
  SSH_PERMIT_ROOT_LOGIN=no
  ...
  ```
- 각 항목별 설명은 osps.conf 파일 내 주석 참고

## 요구사항
- Ubuntu 18.04/20.04/22.04 등 (apt 기반)
- bash, sudo, whiptail 등 기본 유틸리티

## 만든 사람
- **ikkcu (잌쿠)**
- 블로그: [makeit.ikkcu.com](https://makeit.ikkcu.com)

---

> 문의/피드백은 블로그 또는 깃허브 이슈로 남겨주세요. 