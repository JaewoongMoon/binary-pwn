# -*- coding: utf-8 -*-

import binascii
import sys

banner = """
     __          __   _____          _                           
  /\ \ \/\  /\/\ \ \ /__   \___  ___| |__  _ __ ___  _   _ ___   
 /  \/ / /_/ /  \/ /   / /\/ _ \/ __| '_ \| '__/ _ \| | | / __|  
/ /\  / __  / /\  /   / / |  __/ (__| | | | | | (_) | |_| \__ \  
\_\ \/\/ /_/\_\ \/    \/   \___|\___|_| |_|_|  \___/ \__,_|___/  
                                                                 
 __                      _ _           _____                     
/ _\ ___  ___ _   _ _ __(_) |_ _   _  /__   \___  __ _ _ __ ___  
\ \ / _ \/ __| | | | '__| | __| | | |   / /\/ _ \/ _` | '_ ` _ \ 
_\ \  __/ (__| |_| | |  | | |_| |_| |  / / |  __/ (_| | | | | | |
\__/\___|\___|\__,_|_|  |_|\__|\__, |  \/   \___|\__,_|_| |_| |_|
                               |___/

                   NHN Techorus Security Team.

                    Required Python version:

                             2.7 +
                               
                         Written by:
                         
                        Jaewoong Moon

                       Program Version:
                        
                             1.1
"""
# 파일의 바이트 배열이 특정 문자열로 이루어져 있는 부분을 찾는다. 
def main():

    reload(sys)
    sys.setdefaultencoding('utf-8')
    print(banner)

    # *** Argument check and Usage.
    # argv[1] : file path to check
    try:
        filename = sys.argv[1]
    except:
        print("Usage: python binary-flag-hacker.py [file-path-to-check] (optional)[flag-keyword-to-search]")
        exit(1)

    # argv[2] : keyword to search (default: 'flag')
    # 찾고자 하는 키워드 : 대회에 따라 flag, seccon, defcon 등으로 바뀔 것이다.
    try:
        keyword = sys.argv[2]
    except:
        keyword = "flag"

    
    hex_bytes = readBytesFromFile(filename) # 1) 파일을 읽어서 
    hex_arr = makeByteArr(hex_bytes) # 바이트 배열을 만든 후
    #print(hex_arr)
    
    gap_arr = calculateGaps(hex_arr)  # 2) 변위 배열을 계산한다.
    # print (gap_arr)
    
    findFlags(hex_arr, gap_arr, keyword)  # 3) 그리고 키워드의 위치를 찾고 출력한다.

    
# 파일을 헥사값으로 읽어들인다. 
def readBytesFromFile(filename):
    with open(filename, 'rb') as f:
        content = f.read()
    hexcode = binascii.hexlify(content)
    return hexcode


# 헥사값을 두개를 하나의 바이트로 하여 바이트 배열로 변환한다.
def makeByteArr(hex_bytes):
    hexarr = []    
    for i in range(0, len(hex_bytes)/2):
        hexarr.append(hex_bytes[i*2:i*2+2])
    return hexarr


# 바이트 배열로부터 (연속된 두 바이트의 차이 값을 가지고 있는) 변위 배열을 구한다.    
def calculateGaps(hexarr):
    gaparr = []
    for i in range(0, len(hexarr)-1):
        gaparr.append(int(hexarr[i+1],16) - int(hexarr[i],16))
    return gaparr


# 변위 배열의 모든 아이템에 대해 검사를 수행한다.
def findFlags(hex_arr, gaparr, keyword):
    print('Hacking...')

    keyword_diff = getKeywordDiff(keyword)
    
    # 연속된 바이트 배열 값들 중 찾고자 하는 키워드로 보이는 것이 있는지    
    for i in range(0, len(gaparr)-(len(keyword)-1)):

        find = 0
        for j in range (0, len(keyword_diff)):
            if gaparr[i+j] != None:
                if gaparr[i+j] == keyword_diff[j]:
                    find = find + 1
                else:
                    find = 0
        
        # 연속된 키워드의 길이 만큼 찾았을 때: 
        if find == len(keyword) -1 :  
            #print("find: %s at index :%d" % (find, i))
            flag = getFlagString(hex_arr, i, keyword)
            print("**********************************")
            print (flag)
            print("**********************************")
                        
    print('Done.')            


# 키워드의 변위배열을 리턴한다.
# 여기서 변위는 문자의 아스키 값을 숫자로 표현했을 때, 뒤의 문자와 앞의 문자의 차이를 말함. 
# ex) flag
#    -> f 와 l 사이의 차이, l 과 a 사이의 차이, a와 g사이의 차이
#    [ 6, -11, 6]
def getKeywordDiff(keyword):
    result = []
    for i in range(0, len(keyword)-1 ):
        diff = ord(keyword[i+1]) - ord(keyword[i])
        result.append(diff)

    return result


# 플래그로 추정되는 값을 추출한다.
# start_index : f 문자가 시작되는자리.
def getFlagString(hex_arr, start_index, keyword):
    # 1) diff 를 구한다. (첫 인덱스의 자리의 바이트 값과 아스키 코드 f 값의 차이)
    print("%d 번 째 Byte index 부터 찾습니다." % start_index)
    start_val = int(hex_arr[start_index],16)
    diff =  ord(keyword[0]) - start_val

    # 2) 종료되는 위치 (end_index) 를 구한다. 
    # 바이트 배열을 쭉 조사하다가 (배열의 값 + 변위 값 )이  } (0x7d (125)) 이면 그 아이템이 종료 인덱스이다. 
    search = 0x7d  
    end_index = 0
    for i in range(start_index, len(hex_arr)):
        if (int(hex_arr[i],16) + diff) == search:
            end_index = i
            break

    # 3) 추정 값을 생성하고 리턴한다.
    estims = []
    if end_index != 0:
        for i in range(start_index, end_index + 1):
            ascii = (int(hex_arr[i],16) + diff)%256 # 아스키 코드 범위내 변환
            #print ("%d 's ascii: %d" % (i, ascii))
            c = chr(ascii) # 결과 값 문자로 변환
            estims.append(c)
        
    return "".join(str(c) for c in estims)

if __name__ == '__main__':
    main()
