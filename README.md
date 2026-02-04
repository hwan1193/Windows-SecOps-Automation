# Windows-SecOps-Automation
Windows 환경에서의 보안 운영(SecOps) 효율성을 극대화하고, 침해사고 대응(IR) 및 컴플라이언스 준수를 자동화하기 위한 PowerShell 툴킷입니다.

# 🛡️ Windows SecOps & Security Automation Toolkit

본 레포지토리는 기업 환경의 **Windows 인프라 보안 운영(SecOps) 및 침해사고 대응(IR) 프로세스**를 자동화하기 위해 개발된 PowerShell 스크립트 모음입니다. 실무에서의 취약점 탐지, 엔드포인트 보호, 그리고 보안 인증(ISO 27001) 증적 수집을 목적으로 제작되었습니다.

## 🚀 Key Modules

### 1. Vulnerability & Threat Intelligence
* **Log4j & Java Scanner**: 인프라 내 Java 환경 분석 및 Log4j 취약 JAR 파일 정밀 탐색.
* **VulnFeed Collector**: CISA KEV, NVD, KISA(KRCERT)의 최신 취약점 데이터를 수집하여 내부 자산과 매칭 및 Teams 알림 송신.

### 2. Incident Response & Forensics
* **Osquery IR Pipeline**: osquery를 활용해 비정상 프로세스, 외부 소켓, 미서명 바이너리 등 침해 지표(IoC)를 실시간 수집 및 분석.
* **RDP Login Monitor**: Windows 이벤트 로그를 분석하여 RDP 브루트포스 공격 시도를 탐지하고 의심 IP를 식별.

### 3. Endpoint & Network Security
* **Integrated Security Scan**: Nmap(포트 스캔), Trivy(컨테이너/FS 진단), YARA(악성코드 탐색)를 통합하여 매일 9시 자동 보안 점검 및 메일 보고서 발송.
* **Defender Automation**: Intune 환경에서 Microsoft Defender의 정기 정밀 검사를 강제화하는 스케줄러 등록.

### 4. Cloud Native Security (K8s)
* **K8s Security Auditor**: Kubernetes 클러스터의 RBAC 설정, 네트워크 정책, 이미지 태그 보안성(latest 사용 여부 등)을 종합 점검.

---

## 🛠️ Tech Stack
* **Language**: PowerShell 5.1 / 7.x (Core)
* **Security Tools**: Nmap, Trivy, Osquery, YARA, kubectl, Microsoft Defender
* **Operating Systems**: Windows Server 2016/2019/2022, Windows 10/11, Linux (Target)

---

## 👤 Author & Experience
* **Infra/Security Engineer** (5+ Years Experience)
* Expertise in **ISO 27001** Audit, Endpoint Security Management(Intune), and Infrastructure Operation.
* Graduate Research Background in Information Security.
