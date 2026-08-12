# AI SAST for Raspberry Pi Userland

Raspberry Pi userland를 대상으로 구현한 멀티 에이전트형 AI SAST 과제입니다.

## Target

- Repository: https://github.com/raspberrypi/userland
- Local path: `../userland`
- Commit: `a54a0dbb2b8dcf9bafdddfc9a9374fb51d97e976`

## Pipeline

Chunker → Candidate Finder → Context Builder → Gemini Security Reviewer →
Validator → Report Builder 순서로 분석합니다.

## Project structure

- `src`: SAST 구현 코드
- `scripts`: 실행 및 분석 스크립트
- `config`: 분석 설정과 검증 판정
- `prompts`: 실제 Gemini system prompt
- `docs`: 단계별 설계 및 최종 보고서
- `results`: 분석 결과와 비교 자료
- `tests`: 단위 테스트

최종 결과는 [`docs/final-report.md`](docs/final-report.md)를 참조합니다.
제출 전 이 README와 최종 보고서에 작성한 도구의 GitHub 저장소 URL을 추가해야 합니다.
