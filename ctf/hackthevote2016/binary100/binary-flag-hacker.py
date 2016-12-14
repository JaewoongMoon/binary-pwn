# -*- coding: utf-8 -*-
# 바이너리 파일의 바이트 배열이 "flag{" 라는 문자열로 이루어져 있을 가능성이 큰 부분을 찾는다. 
import binascii
filename='/root/binary-pwn/ctf/hackthevote2016/binary100/consul.dcdcdac48cdb5ca5bc1ec29ddc53fb554d814d12094ba0e82f84e0abef065711'

def main():
    hex_bytes = readBytesFromFile(filename)
    hex_arr = makeByteArr(hex_bytes)
    # print(hex_arr)
    gap_arr = calculateGaps(hex_arr)
    # print (gap_arr)
    findFlags(hex_arr, gap_arr)
    
# 1. 파일로부터 바이트 형식으로 읽어들인다. 
def readBytesFromFile(filename):
    with open(filename, 'rb') as f:
        content = f.read()
    hexcode = binascii.hexlify(content)
    return hexcode

# 2. 파일의 전체 바이트를 배열에 담는다. 
def makeByteArr(hex_bytes):
    hexarr = []    
    for i in range(0, len(hex_bytes)/2):
        hexarr.append(hex_bytes[i*2:i*2+2])
    return hexarr

# 3. 바이트 배열로부터 (연속된 두 바이트의 차이 값을 가지고 있는) 변위 배열을 구한다.    
def calculateGaps(hexarr):
    gaparr = []
    for i in range(0, len(hexarr)-1):
        gaparr.append(int(hexarr[i+1],16) - int(hexarr[i],16))
    return gaparr

# 4. 변위 배열의 모든 아이템에 대해 검사를 수행한다.
#  (연속된 변위가 (0x6 (6), -0xB (-11), 0x6 (6), 0xF(15) 인지)
def findFlags(hex_arr, gaparr):
    print('Hacking...')
    
    for i in range(0, len(gaparr)-2):
        if gaparr[i] != None and gaparr[i+1] != None and gaparr[i+2] != None:
            if gaparr[i] == 6 and gaparr[i+1] == -11 and gaparr[i+2] == 6:
                print("플래그로 추정되는 위치를 찾았습니다!")
                flag = getFlagString(hex_arr, i) 
                print (flag)
    
    print('Done.')            
                
        
# 플래그로 추정되는 값을 추출한다. ]
# start_index : f 문자가 시작되는자리.
def getFlagString(hex_arr, start_index):
    # 1) diff 를 구한다. (첫 인덱스의 자리의 바이트 값과 아스키 코드 f 값의 차이)
    print("%d 인덱스에서부터 찾습니다." % start_index)
    start_val = int(hex_arr[start_index],16)
    diff =  0x66 - start_val
    print("diff는 %d로 추정됩니다..." % diff)
    start_point_val = start_val + diff 
    # print("start 지점 값 : %s" % chr(start_point_val) )

    # 2) end_index 를 구한다. 
    # start_index 에서 시작해서 문자 } 까지 이다. 
    # 문자 } 는 0x7d (125) 이다. 
    # hex_arr 의 아이템과 diff 를 더한 값이 0x7d(125) 이면 그 아이템이 종료 인덱스이다.
    search = 0x7d
    end_index = 0
    for i in range(start_index, len(hex_arr)):
        if (int(hex_arr[i],16) + diff) == search:
            end_index = i
            print("플래그가 종료되는 위치를 찾았습니다. %d 인덱스까지 찾습니다. " % end_index)      
            break

    # 3) 추정 값을 생성하고 리턴한다.
    estims = []
    if end_index != 0:
        for i in range(start_index, end_index + 1):
            ascii = (int(hex_arr[i],16) + diff)%256 # 아스키 코드 범위내 변환
            print ("%d 's ascii: %d" % (i, ascii))
            c = chr(ascii) # 결과 값 문자로 변환
            estims.append(c)
        
    return "".join(str(c) for c in estims)

if __name__ == '__main__':
    main()
