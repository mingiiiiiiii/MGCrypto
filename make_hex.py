# data = """
# 24,8D,6A,61,D2,06,38,B8,E5,C0,26,93,0C,3E,60,39,A3,3C,E4,59,64,FF,21,67,F6,EC,ED,D4,19,DB,06,C1
# """

# # 전처리
# byte_list = data.replace('\n', '').replace(' ', '').split(',')
# byte_list = [f'0x{b.upper()}' for b in byte_list if b]

# # 16개 단위로 나눠서 출력
# lines = []
# for i in range(0, len(byte_list), 16):
#     chunk = ', '.join(byte_list[i:i+16])
#     lines.append(f"    {chunk}")

# # 최종 배열 출력
# print("ans[] = {\n" + ',\n'.join(lines) + "\n};")

# data = """
# 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
# 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 
# """

# # 전처리: 문자열 분해 후 각 32비트 값을 4바이트 big endian으로 쪼갬
# hex_words = data.replace('\n', ' ').split()
# byte_list = []

# for word in hex_words:
#     # 32비트 정수를 big-endian으로 쪼갬 (상위 바이트부터)
#     byte_list.extend([f'0x{word[i:i+2]}' for i in range(0, 8, 2)])

# # 16바이트씩 출력 정렬
# lines = []
# for i in range(0, len(byte_list), 16):
#     chunk = ', '.join(byte_list[i:i+16])
#     lines.append(f"    {chunk}")

# # 최종 출력
# print("ans[] = {\n" + ',\n'.join(lines) + "\n};")

data = """
36b89649a59e58bdb83daef360ff65aac2630460ca606b1bfc1eb0172e56c7c3
f956a3a840ae99c845cf2cbfc92c09b1614375f57b59054439d8d94e898a15cf
"""

# 줄바꿈/공백 제거 + 2글자씩 잘라서 바이트 리스트 생성
cleaned = data.replace('\n', '').replace(' ', '')
byte_list = [f'0x{cleaned[i:i+2]}' for i in range(0, len(cleaned), 2)]

# 16개 단위로 줄바꿈 정렬
lines = []
for i in range(0, len(byte_list), 16):
    chunk = ', '.join(byte_list[i:i+16])
    lines.append(f"    {chunk}")

# 최종 출력
print("ans[] = {\n" + ',\n'.join(lines) + "\n};")
