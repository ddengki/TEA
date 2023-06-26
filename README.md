# TEA
File Encryption and Decryption using TEA Algorithm with C lang

## Explanation
TEA 대칭키 알고리즘을 이용한 파일 암호화/복호화
❑ 프로그램 활용 (CMD 창의 프로그램 호출 예)
tea -e ecb test.pdf (test.pdf를 ECB 모드로 암호화하여 test.pdf.tea 파일 생성)
tea -d ecb test.pdf.tea (test.pdf를 ECB 모드로 복호화하여 test.pdf 파일 복원)
tea -e cbc test.pdf (test.pdf를 CBC 모드로 암호화하여 test.pdf.tea 파일 생성)
tea -d cbc test.pdf.tea (test.pdf를 CBC 모드로 복호화하여 test.pdf 파일 생성)
❑ 사용자의 암호 입력
10글자 이상을 입력 받음 (원래 TEA는 128bit(16자)이지만, 모자란 바이트는 0으로 패딩)
파일 암호화 시에는 동일한 암호를 한번 더 입력하도록 함
❑ 암호화 시 파일 구성
Header 생성: 8바이트 길이, “TEA(널)ECB(널)” 또는 “TEA(널)CBC(널)”
ECB: C0(Header)+C1+C2+…
CBC: IV(랜덤)+C0(Header)+C1+C2+…
마지막 블록이 8바이트 미만일 경우, 그 크기 만큼만 파일로 저장
❑ 복호화 시 동작
사용자의 암호를 입력 받아서 Header를 복호화하여 “TEA(널)ECB(널)”
또는 “TEA(널)CBC(널)” 형태로 복호화 되지 않으면 암호가 틀렸다고
사용자에게 통보하고 종료
Header와 IV는 파일 복원에 제외하여 암호화 전의
파일과 완전히 동일하게 복원되어야 함

