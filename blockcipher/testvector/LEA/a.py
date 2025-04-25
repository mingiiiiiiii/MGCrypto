import os
print("현재 작업 디렉토리:", os.getcwd())


folder_path = "/home/mingiiiiiiii/MGCrypto/blockcipher/testvector/LEA"


# 폴더 내의 모든 파일 목록을 가져옵니다
for filename in os.listdir(folder_path):
    # 파일이 .txt 확장자로 끝나는 경우
    if filename.endswith('.txt'):
        old_name = os.path.join(folder_path, filename)
        new_name = os.path.join(folder_path, filename.rsplit('.', 1)[0] + '.fax')
        
        try:
            os.rename(old_name, new_name)  # 파일 이름 변경
            print(f"파일 이름이 '{old_name}'에서 '{new_name}'로 변경되었습니다.")
        except Exception as e:
            print(f"파일 이름 변경 실패: {e}")