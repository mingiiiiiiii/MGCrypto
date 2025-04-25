import os

# 파일들이 있는 폴더 경로 설정
folder_path = "/home/mingiiiiiiii/MGCrypto/blockcipher/testvector/AES" # 폴더 경로를 실제 경로로 변경하세요


# 폴더 내의 모든 파일을 확인
for filename in os.listdir(folder_path):
    if filename.endswith('.fax'):  # .fax 확장자 파일만 처리
        file_path = os.path.join(folder_path, filename)
        
        # 파일 읽기
        with open(file_path, 'r') as file:
            lines = file.readlines()
        
        # 대문자로 변환 후 다시 파일에 쓰기
        with open(file_path, 'w') as file:
            for line in lines:
                file.write(line.upper())  # 소문자를 대문자로 변환해서 저장

        print(f"파일 '{filename}'의 모든 내용을 대문자로 변환했습니다.")