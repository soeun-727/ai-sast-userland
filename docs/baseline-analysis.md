# Baseline Analysis

## 1. 분석 대상

- Repository: https://github.com/raspberrypi/userland
- Local path: ../userland
- Branch: master
- Commit: a54a0dbb2b8dcf9bafdddfc9a9374fb51d97e976
- Commit date: 2024-12-23 13:52:07 +1100
- Analysis environment: Windows PowerShell 5.1

분석 대상 저장소는 과제 도구 저장소 외부에 별도로 복제하였다.
원본 저장소에는 별도의 변경 사항을 적용하지 않았다.

## 2. 저장소 통계

### 2.1 언어별 파일 수

| 확장자 | 파일 수 |
|---|---:|
| .h | 367 |
| .c | 284 |
| .cpp | 3 |
| 합계 | 654 |

C 및 C++ 구현 파일은 총 287개이며, 헤더 파일을 포함하면
분석 대상 C/C++ 관련 파일은 총 654개이다.

### 2.2 컴포넌트별 파일 수

| 컴포넌트 | 파일 수 |
|---|---:|
| interface | 371 |
| host_applications | 127 |
| containers | 104 |
| middleware | 20 |
| opensrc | 13 |
| helpers | 8 |
| vcfw | 5 |
| vcinclude | 3 |
| host_support | 2 |
| makefiles | 1 |

interface가 371개로 가장 많은 C/C++ 관련 파일을 포함한다.
그다음은 host_applications 127개, containers 104개 순이다.

파일 수가 특정 컴포넌트에 집중되어 있으므로 저장소 전체를
한 번에 LLM에 입력하기보다는 컴포넌트와 함수 단위로 나누어
분석할 필요가 있다.

## 3. 대형 파일

확인된 대형 소스 파일 중 일부는 다음과 같다.

| 크기 | 파일 |
|---:|---|
| 178.88 KB | interface/khronos/glxx/glxx_client.c |
| 172.62 KB | interface/khronos/vg/vg_client.c |
| 170.63 KB | host_applications/linux/apps/hello_pi/hello_tiger/tiger.c |
| 108.18 KB | interface/vmcs_host/khronos/IL/OMX_Broadcom.h |
| 101.36 KB | host_applications/linux/apps/raspicam/RaspiVid.c |
| 95.64 KB | containers/mkv/matroska_reader.c |
| 90.52 KB | containers/asf/asf_reader.c |
| 87.91 KB | helpers/dtoverlay/dtoverlay.c |
| 87.12 KB | interface/khronos/egl/egl_client.c |

가장 큰 파일은 약 178.88 KB이며, 파일 전체를 하나의 프롬프트로
분석하는 것은 토큰 사용량과 분석 정확도 측면에서 비효율적이다.
따라서 대형 파일은 함수 또는 의미 있는 코드 블록 단위로 분할한다.

## 4. 빌드 구조

저장소의 최상위 경로와 여러 하위 컴포넌트에
CMakeLists.txt가 존재한다. 따라서 주요 빌드 시스템은
CMake인 것으로 확인하였다.

CMake 빌드 파일은 다음과 같은 영역에서 확인되었다.

- 저장소 최상위 경로
- containers
- containers/asf
- containers/avi
- containers/mkv
- containers/mp4
- containers/mpeg
- containers/rtp
- containers/rtsp

대상 프로젝트는 Raspberry Pi 및 Linux 환경에 종속된 코드를
포함할 가능성이 있으므로 Windows 환경에서 전체 빌드가 가능한지는
추가 확인이 필요하다. 초기 SAST 구현은 전체 빌드 성공에 의존하지
않는 소스 코드 인덱싱 방식으로 진행한다.

## 5. 위험 API 조사

문자열 처리, 메모리 처리, 파일 처리 및 프로세스 실행과 관련된
API를 대상으로 1차 패턴 검색을 수행하였다.

검색 대상에는 다음과 같은 API가 포함되었다.

- 문자열 처리: strcpy, strcat, sprintf, vsprintf, gets, scanf, sscanf
- 메모리 처리: memcpy, memmove, malloc, calloc, realloc, free
- 프로세스 실행: system, popen, exec 계열
- 파일 처리: fopen, open

검색 결과 총 832개의 위험 API 출현(occurrence)이 후보로 수집되었다.

이 수치는 확정된 취약점 수가 아니다. 함수 선언, 안전하게 검증된
API 사용, 주석 또는 보안 문제가 없는 정상 코드가 포함될 수 있다.
따라서 이후 단계에서 함수 문맥, 입력값의 출처, 크기 검사 여부 및
호출 관계를 분석해야 한다.

## 6. 초기 분석 범위

### 6.1 포함 대상

- .c, .cpp 구현 파일
- 프로젝트에서 직접 사용하는 .h 헤더
- 문자열 및 입력 처리 코드
- 메모리 할당, 해제 및 복사 코드
- 파일 입출력 코드
- 프로세스 및 시스템 호출 관련 코드
- 데이터 파서와 컨테이너 처리 코드

### 6.2 제외 대상

- .git 내부 파일
- 빌드 산출물
- 바이너리 및 미디어 파일
- 실행 코드가 아닌 데이터 파일

### 6.3 낮은 우선순위 대상

- 예제 코드
- 테스트 코드
- 명확하게 식별되는 외부 오픈소스 코드
- 자동 생성된 코드 또는 대규모 상수 데이터

낮은 우선순위 대상은 완전히 제외하지 않고 별도로 표시한다.
이는 저장소 전체 탐색 요구사항을 유지하면서 핵심 제품 코드에
분석 자원을 우선 배정하기 위함이다.

## 7. 기준선 SAST

기존 SAST와의 비교를 위해 Cppcheck 2.21.0을 기준 도구로 실행하였다.

기록할 항목은 다음과 같다.

- Cppcheck 버전
- 실행 명령
- 실행 시간
- 분석된 파일 수
- 전체 경고 수
- 경고 유형별 수
- 파싱 실패 또는 분석 제외 파일
- AI SAST 결과와 중복되는 결과

전체 저장소에서는 60.648초 동안 1,637개 진단이 생성되었고, AI와
동일한 3개 파일에서는 1.212초 동안 84개 진단이 생성되었다. 상세 옵션,
등급별 통계 및 AI 결과와의 교집합은
[`cppcheck-comparison.md`](cppcheck-comparison.md)에 기록하였다.

## 8. 코드 분할 전략에 주는 시사점

기준선 분석 결과를 바탕으로 다음 분할 원칙을 적용한다.

1. 저장소를 주요 컴포넌트 단위로 구분한다.
2. 각 컴포넌트의 파일을 함수 단위로 분할한다.
3. 파일 경로와 원본 줄 번호를 보존한다.
4. 위험 API가 포함된 함수를 우선 분석 대상으로 지정한다.
5. 함수 분석에 필요한 선언과 호출 관계만 추가 문맥으로 제공한다.
6. 대형 파일을 전체 프롬프트에 직접 입력하지 않는다.
7. 이미 분석한 공통 헤더와 함수 요약은 캐시하여 재사용한다.

## 9. 확정 분석 배치

분석 결과를 제시할 세 배치는 서로 다른 보안 특성을 갖도록
구성하였다.

### Batch 1: 문자열 및 입력 처리

- 문자열 복사와 포맷 처리
- 사용자 또는 외부 입력 처리
- 버퍼 길이와 경계 검사

### Batch 2: 파일 및 시스템 처리

- 파일 경로 처리
- 파일 열기와 읽기
- 프로세스 및 시스템 호출

### Batch 3: 메모리 및 포인터 처리

- 동적 메모리 할당과 해제
- 메모리 복사
- 포인터와 크기 계산

실제 대상 파일과 선정 이유는 `config/batches.yml`에 고정하였다.

## 10. 한계

- 위험 API 검색은 단순 패턴 검색이므로 오탐이 포함될 수 있다.
- Windows 환경에서 전체 프로젝트 빌드 가능 여부를 확인하지 않았다.
- 함수 호출 관계는 직접 호출 한 단계까지만 후속 Context Builder에서 분석했다.
- Cppcheck 전체 결과에는 Windows에서 대상 빌드 구성 없이 분석해 발생한
  전처리 및 파싱 진단이 포함될 수 있다.
- 전체 코드 줄 수는 별도로 측정하지 않았으며 파일 수와 선택 배치 통계를 사용한다.
