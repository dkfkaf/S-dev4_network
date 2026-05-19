# CLAUDE.md

## Project Overview
이 프로젝트는 **실제로 캡처한 무선 패킷(raw wireless packets)** 을 입력으로 받아  
**802.11 management frame parser** 를 구현하는 C++ 프로젝트입니다.

기존에 `csa/` 폴더가 이미 존재하며, Claude는 반드시 먼저 해당 폴더의 구조와 코드를 읽고 이해한 뒤,  
**기존 구현을 확장하는 방식으로 개발**해야 합니다.  
새 프로젝트를 처음부터 다시 만드는 방식보다, 현재 코드베이스와 호환되도록 기능을 추가하는 방식을 우선합니다.

---

## Main Goal
잡은 무선 패킷 데이터에서 다음 802.11 management frame을 파싱합니다.

- Beacon
- Probe Request
- Probe Response
- Deauthentication
- Authentication
- Association Request
- Association Response

그리고 각 프레임에서 아래 정보를 추출합니다.

- SSID
- BSSID
- Source MAC
- Destination MAC
- RSSI (가능하면 Radiotap 또는 기존 메타데이터 기반)

---

## Important Instruction
Claude는 작업 시작 전에 반드시 아래 순서로 진행합니다.

1. `csa/` 폴더의 전체 구조를 확인합니다.
2. `csa/` 폴더 안의 기존 C++ 코드, 헤더, 빌드 파일(CMake 포함)을 읽고 현재 구현 방식을 파악합니다.
3. 현재 프로젝트의 네이밍 규칙, 코드 스타일, 파서 구조를 최대한 유지합니다.
4. 새로운 기능은 **기존 코드에 통합되는 형태로 추가**합니다.
5. 이미 있는 기능과 중복되는 구현을 새로 만들지 않습니다.
6. 구조 변경이 필요하다면 최소 범위로 진행합니다.

즉, Claude는 **먼저 csa 폴더를 분석하고, 그 다음 확장 구현**을 해야 합니다.

---

## Tech Stack
- Language: C++17
- Build System: CMake
- Directory policy:
  - `src/` → `.cpp`
  - `include/` → `.h`

---

## Directory Structure Policy
기본적으로 아래 구조를 유지하거나, 기존 `csa/` 구조에 맞춰 확장합니다.

```text
project-root/
├─ CMakeLists.txt
├─ CLAUDE.md
├─ csa/
├─ include/
├─ src/
└─ samples/