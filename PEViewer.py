# -*- coding: utf-8 -*-
# 클래스 선언부#

class hander(object):
    global ex # 글로벌 함수 설정
    try:
        #
        file_name = raw_input("파일 이름을 입력해 주세요 : ")
        f = open(file_name, 'rb')
        print("파일을 불러오는데 성공 했습니다.")
        data = f.read()
        f.close()
        ex = 1

    except:
        print("파일을 불러오는데 실패 했습니다.")
        ex = -1

    ##Hex에디터 모드-Dos Header
    def Hexmod_Dos_Header_output(self):
        lib = self.data
        hex_code = lib.encode('hex')
        offset = 0
        print("================================PEfile View================================")
        #옵션 출력
        print '%-15s' % "Offset(h)",
        for i in range(16):
            if (i == 15):
                print "%.2x" % i
            else:
                print "%.2x" % i,
        i = 0
        #리드 시작
        while(i<80):
            if (i == 0):
                print"%.8x%10s" % (offset, hex_code[i:i + 2]),
                i += 1
            elif ((i + 1) % 16 == 0):
                print(hex_code[i * 2:(i + 1) * 2])
                offset += 16
                i += 1
            elif ((i + 1) % 16 == 1):
                print "%.8x%10s" % (offset, hex_code[i*2:(i + 1) * 2]),
                i += 1
            else:
                print hex_code[i * 2:(i + 1) * 2],
                i += 1

    ##PE모드-Dos_Header
    def Dos_Header_output(self):

        # 파일 리스트화
        Dos_Headaer = ["WORD   e_magic;", "WORD   e_cblp;", "WORD   e_cp;", "WORD   e_crlc;",
                       "WORD   e_cparhdr;", "WORD   e_minalloc;", "WORD   e_maxalloc;",
                       "WORD   e_ss;", "WORD   e_sp;", "WORD   e_csum;", "WORD   e_ip;",
                       "WORD   e_cs;", "WORD   e_lfarlc;", "WORD   e_ovno;", "WORD   e_res[4];",
                       "WORD   e_oemid;", "WORD   e_oeminfo;", "WORD   e_res2[10];", "LONG   e_lfanew;"]
        lib = self.data
        hex_code = lib.encode('hex')
        offset = 0
        print("================================PEfile View================================")
        print '%-15s' % "Offset(h)  Data %9s %8s" % ("Byte", "Value")
        seting = 1
        Header_list = Dos_Headaer
        i = 0

        while (i < 80):
            count = 0
            if (Header_list[0] != "WORD   e_res[4];" and Header_list[0] != "WORD   e_res2[10];" and Header_list[
                0] != "LONG   e_lfanew;"):
                output_list = Header_list.pop(0)
                if (i == 0):
                    #리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i:i + 4]
                    endian = []
                    while(row<4):
                        endian.append(endian_data[row:row+2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while(row<2):
                        output_endian += endian.pop(0)
                        row += 1
                    #출력 부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 1
                else:
                    #리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i*4:(i+1) * 4]
                    endian = []
                    while(row<4):
                        endian.append(endian_data[row:row+2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while(row<2):
                        output_endian += endian.pop(0)
                        row += 1
                    #출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 1
            elif (Header_list[0] == "WORD   e_res2[10];"):
                output_list = Header_list.pop(0)
                while (count < 10):
                    #리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i*4:(i+1) * 4]
                    endian = []
                    while(row<4):
                        endian.append(endian_data[row:row+2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while(row<2):
                        output_endian += endian.pop(0)
                        row += 1
                    #출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    count += 1
                    offset += 2
                    i += 1

            elif (Header_list[0] == "WORD   e_res[4];"):
                output_list = Header_list.pop(0)
                while (count < 4):
                    #리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i*4:(i+1) * 4]
                    endian = []
                    while(row<4):
                        endian.append(endian_data[row:row+2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while(row<2):
                        output_endian += endian.pop(0)
                        row += 1
                    #출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    count += 1
                    offset += 2
                    i += 1
            elif (Header_list[0] == "LONG   e_lfanew;"):
                output_list = Header_list.pop(0)
                #리틀 엔디언 적용하기
                row = 0
                output_endian = ""
                endian_data = hex_code[i * 4:(i + 2) * 4]
                endian = []
                while(row<8):
                    endian.append(endian_data[row:row+2])
                    row += 2
                row = 0
                endian.reverse()
                while(row<4):
                    output_endian += endian.pop(0)
                    row += 1
                print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                offset += 4

    ##Hex에디터 모드-Dos Stub
    def Hexmod_Dos_Stub_output(self):
        lib = self.data
        hex_code = lib.encode('hex')
        offset = 80-16
        print("================================PEfile View================================")
        #옵션 출력
        print '%-15s' % "Offset(h)",
        for i in range(16):
            if (i == 15):
                print "%.2x" % i
            else:
                print "%.2x" % i,
        i = 80-16
        #리드 시작
        while(i<160+16*3):
            if (i == 0):
                print"%.8x%10s" % (offset, hex_code[i:i + 2]),
                i += 1
            elif ((i + 1) % 16 == 0):
                print(hex_code[i * 2:(i + 1) * 2])
                offset += 16
                i += 1
            elif ((i + 1) % 16 == 1):
                print "%.8x%10s" % (offset, hex_code[i*2:(i + 1) * 2]),
                i += 1
            else:
                print hex_code[i * 2:(i + 1) * 2],
                i += 1

    ##Hex에디터 모드-NT Headers
    def Hexmod_NT_Headers_output(self):
        lib = self.data
        hex_code = lib.encode('hex')
        offset = 208
        print("================================PEfile View================================")
        #옵션 출력
        print '%-15s' % "Offset(h)",
        for i in range(16):
            if (i == 15):
                print "%.2x" % i
            else:
                print "%.2x" % i,
        i = 208
        #리드 시작
        while(i<456):
            if (i == 0):
                print"%.8x%10s" % (offset, hex_code[i:i + 2]),
                i += 1
            elif ((i + 1) % 16 == 0):
                print(hex_code[i * 2:(i + 1) * 2])
                offset += 16
                i += 1
            elif ((i + 1) % 16 == 1):
                print "%.8x%10s" % (offset, hex_code[i*2:(i + 1) * 2]),
                i += 1
            else:
                print hex_code[i * 2:(i + 1) * 2],
                i += 1
        print("\n")

    ##PE모드-NT Headers
    def NT_Headers_output(self):
        output_list = ["LONG   IMAGE_NT_SIGNATURE PE;"]
        lib = self.data
        hex_code = lib.encode('hex')
        #옵션 출력
        print("================================PEfile View================================")
        print '%-15s' % "Offset(h)  Data %9s %8s" % ("Byte", "Value")
        i = 208
        offset = 208
        NT_Headers_output =output_list.pop()
        # 리틀 엔디언 적용하기
        row = 0
        output_endian = ""
        endian_data = hex_code[i * 2 :(i + 2)*4]
        endian = []
        while (row < 8):
            endian.append(endian_data[row:row + 2])
            row += 2
        row = 0
        endian.reverse()
        while (row < 4):
            output_endian += endian.pop(0)
            row += 1
        print "%.8x   %-10s%s" % (offset, output_endian, NT_Headers_output)

    ##PE모드 -IMAGE_FILE_HEADER
    def IMAGE_FILE_HEADER_output(self):
        Image_file = ["WORD    Machine;", "WORD    NumberOfSections;", "DWORD   TimeDateStamp;",
                    "DWORD   PointerToSymbolTable;", "DWORD   NumberOfSymbols;",
                    "WORD    SizeOfOptionalHeader;", "WORD    Characteristics;"]
        lib = self.data
        hex_code = lib.encode('hex')
        print("================================PEfile View================================")
        print '%-15s' % "Offset(h)  Data %9s %8s" % ("Byte", "Value")
        seting = 1
        Header_list = Image_file
        i = 212
        offset = 212
        while (1):
            count = 0
            if (Header_list[0] != "DWORD   TimeDateStamp;" and Header_list[0] != "DWORD   NumberOfSymbols;" and Header_list[
                0] != "DWORD   PointerToSymbolTable;"):
                output_list = Header_list.pop(0)
                if (i == 212):
                    #리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i*2:(i + 4) * 2]
                    endian = []
                    while(row<4):
                        endian.append(endian_data[row:row+2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while(row<2):
                        output_endian += endian.pop(0)
                        row += 1
                    #출력 부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
                else:
                    #리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i*2:(i + 4) * 2]
                    endian = []
                    while(row<4):
                        endian.append(endian_data[row:row+2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while(row<2):
                        output_endian += endian.pop(0)
                        row += 1
                    #출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
            else:
                output_list = Header_list.pop(0)
                #리틀 엔디언 적용하기
                row = 0
                output_endian = ""
                endian_data = hex_code[i*2:(i + 4) * 2]
                endian = []
                while(row<8):
                    endian.append(endian_data[row:row+2])
                    row += 2
                row = 0
                endian.reverse()
                while(row<4):
                    output_endian += endian.pop(0)
                    row += 1
                print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                offset += 4
                i += 4

    ##PE모드-IMAGE_OPTIONAL_HEADER
    def IMAGE_OPTIONAL_HEADER(self):
        Image_optional = ['WORD    Magic;','BYTE    MajorLinkerVersion;','BYTE    MinorLinkerVersion;',
                          'DWORD   SizeOfCode;','DWORD   SizeOfInitializedData;','DWORD   SizeOfUninitializedData;',
                          'DWORD   AddressOfEntryPoint;','DWORD   BaseOfCode;','DWORD   BaseOfData;','DWORD   ImageBase;',
                          'DWORD   SectionAlignment;','DWORD   FileAlignment;','WORD    MajorOperatingSystemVersion;','WORD    MinorOperatingSystemVersion;',
                          'WORD    MajorImageVersion;','WORD    MinorImageVersion;','WORD    MajorSubsystemVersion;','WORD    MinorSubsystemVersion;',
                          'DWORD   Win32VersionValue;','DWORD   SizeOfImage;','DWORD   SizeOfHeaders;','DWORD   CheckSum;',
                          'WORD    Subsystem;','WORD    DllCharacteristics;','DWORD   SizeOfStackReserve;','DWORD   SizeOfStackCommit;',
                          'DWORD   SizeOfHeapReserve;','DWORD   SizeOfHeapCommit;','DWORD   LoaderFlags;','DWORD   NumberOfRvaAndSizes;',
                          'IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];']
        lib = self.data
        hex_code = lib.encode('hex')
        print("================================PEfile View================================")
        print '%-15s' % "Offset(h)  Data %9s %8s" % ("Byte", "Value")
        seting = 1
        Header_list = Image_optional
        i = 232
        offset = 232
        while (1):
            count = 0
            if (Header_list[0][0] == "W"):
                output_list = Header_list.pop(0)
                if (i == 212):
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력 부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
                else:
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
            elif(Header_list[0][0] == "B"):
                output_list = Header_list.pop(0)
                # 리틀 엔디언 적용하기
                row = 0
                output_endian = ""
                endian_data = hex_code[i * 2:(i + 1) * 2]
                endian = []
                while (row < 8):
                    endian.append(endian_data[row:row + 2])
                    row += 2
                row = 0
                endian.reverse()
                while (row < 4):
                    output_endian += endian.pop(0)
                    row += 1
                print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                offset += 1
                i += 1
            elif(Header_list[0][0] == "I"):
                DATA_list = ["RVA   EXPORT Table","Size","RVA   IMPORT Table","Size","RVA   RESOURCE Table",
                             "Size", "RVA   EXCEPTION Table","Size","RVA   CERTUFUCATE Table","Size","RVA   BASE RELOCATION Table",
                             "Size", "RVA   DEBUG Directroy","Size","RVA   Architecture Specific Data",
                             "Size", "RVA   GLOBAL POINTER Register","Size","RVA   TLS Table","Size",
                             "RVA   LOAD CONFIGURATION Table","Size","RVA   BOUND IMPORT Table","Size",
                             "RVA   IMPORT Address Table","Size","RVA   DELAY IMPORT Descriptors","Size","RVA   CLI Header",
                             "Size","RVA  ","Size"]
                print("-"*80)
                count = 0
                while(1):
                    output_list = DATA_list.pop(0)
                    if(output_list[0]=="R"):
                    # 리틀 엔디언 적용하기
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    else:
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    count += 1
                    if(count%2==0):
                        print("-" * 80)
            else:
                output_list = Header_list.pop(0)
                # 리틀 엔디언 적용하기
                row = 0
                output_endian = ""
                endian_data = hex_code[i * 2:(i + 4) * 2]
                endian = []
                while (row < 8):
                    endian.append(endian_data[row:row + 2])
                    row += 2
                row = 0
                endian.reverse()
                while (row < 4):
                    output_endian += endian.pop(0)
                    row += 1
                print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                offset += 4
                i += 4

    ##PE-IMAGE_SECTION_HEADER .text
    def IMAGE_SETION_HEADER_text(self):
        global Qtext
        Image_file = ["DWORD    Name;    .text","DWORD    ","DWORD    Virtual Size;","DWORD    RVA;",
                      "DWORD    Size of Raw Data;","DWORD    Pointer to Raw Data;","DWORD    Pointer to Relocations;",
                      "DWORD    Pointer to Line Numbers;","WORD    Number of Relocations;","WORD    Number of Line Number;",
                      "DWORD    Characteristics;"]
        lib = self.data
        hex_code = lib.encode('hex')
        print("================================PEfile View================================")
        print '%-15s' % "Offset(h)  Data %9s %8s" % ("Byte", "Value")
        seting = 1
        Header_list = Image_file
        i = 456
        offset = 456
        while (1):
            count = 0
            if (Header_list[0][0] == "W"):
                output_list = Header_list.pop(0)
                if (i == 212):
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력 부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
                else:
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
            elif(Header_list[0][0] == "B"):
                output_list = Header_list.pop(0)
                # 리틀 엔디언 적용하기
                row = 0
                output_endian = ""
                endian_data = hex_code[i * 2:(i + 1) * 2]
                endian = []
                while (row < 8):
                    endian.append(endian_data[row:row + 2])
                    row += 2
                row = 0
                endian.reverse()
                while (row < 4):
                    output_endian += endian.pop(0)
                    row += 1
                print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                offset += 1
                i += 1
            elif(Header_list[0][0] == "I"):
                DATA_list = ["RVA   EXPORT Table","Size","RVA   IMPORT Table","Size","RVA   RESOURCE Table",
                             "Size", "RVA   EXCEPTION Table","Size","RVA   CERTUFUCATE Table","Size","RVA   BASE RELOCATION Table",
                             "Size", "RVA   DEBUG Directroy","Size","RVA   Architecture Specific Data",
                             "Size", "RVA   GLOBAL POINTER Register","Size","RVA   TLS Table","Size",
                             "RVA   LOAD CONFIGURATION Table","Size","RVA   BOUND IMPORT Table","Size",
                             "RVA   IMPORT Address Table","Size","RVA   DELAY IMPORT Descriptors","Size","RVA   CLI Header",
                             "Size","RVA  ","Size"]
                print("-"*80)
                count = 0
                while(1):
                    output_list = DATA_list.pop(0)
                    if(output_list[0]=="R"):
                    # 리틀 엔디언 적용하기
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    else:
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    count += 1
                    if(count%2==0):
                        print("-" * 80)
            else:
                if(Header_list[0] == "DWORD    Pointer to Raw Data;"):
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    a = output_endian
                    Qtext = int(a, 16)
                else:
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4

    ##PE-IMAGE SECTION HEADER .rdata
    def IMAGE_SETION_HEADER_rdata(self):
        global Qrdata
        Image_file = ["DWORD    Name;    .rdata","DWORD    ","DWORD    Virtual Size;","DWORD    RVA;",
                      "DWORD    Size of Raw Data;","DWORD    Pointer to Raw Data;","DWORD    Pointer to Relocations;",
                      "DWORD    Pointer to Line Numbers;","WORD    Number of Relocations;","WORD    Number of Line Number;",
                      "DWORD    Characteristics;"]
        lib = self.data
        hex_code = lib.encode('hex')
        print("================================PEfile View================================")
        print '%-15s' % "Offset(h)  Data %9s %8s" % ("Byte", "Value")
        seting = 1
        Header_list = Image_file
        i = 496
        offset = 496
        while (1):
            count = 0
            if (Header_list[0][0] == "W"):
                output_list = Header_list.pop(0)
                if (i == 212):
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력 부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
                else:
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
            elif(Header_list[0][0] == "B"):
                output_list = Header_list.pop(0)
                # 리틀 엔디언 적용하기
                row = 0
                output_endian = ""
                endian_data = hex_code[i * 2:(i + 1) * 2]
                endian = []
                while (row < 8):
                    endian.append(endian_data[row:row + 2])
                    row += 2
                row = 0
                endian.reverse()
                while (row < 4):
                    output_endian += endian.pop(0)
                    row += 1
                print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                offset += 1
                i += 1
            elif(Header_list[0][0] == "I"):
                DATA_list = ["RVA   EXPORT Table","Size","RVA   IMPORT Table","Size","RVA   RESOURCE Table",
                             "Size", "RVA   EXCEPTION Table","Size","RVA   CERTUFUCATE Table","Size","RVA   BASE RELOCATION Table",
                             "Size", "RVA   DEBUG Directroy","Size","RVA   Architecture Specific Data",
                             "Size", "RVA   GLOBAL POINTER Register","Size","RVA   TLS Table","Size",
                             "RVA   LOAD CONFIGURATION Table","Size","RVA   BOUND IMPORT Table","Size",
                             "RVA   IMPORT Address Table","Size","RVA   DELAY IMPORT Descriptors","Size","RVA   CLI Header",
                             "Size","RVA  ","Size"]
                print("-"*80)
                count = 0
                while(1):
                    output_list = DATA_list.pop(0)
                    if(output_list[0]=="R"):
                    # 리틀 엔디언 적용하기
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    else:
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    count += 1
                    if(count%2==0):
                        print("-" * 80)
            else:
                if(Header_list[0] == "DWORD    Pointer to Raw Data;"):
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    a = output_endian
                    Qrdata = int(a, 16)
                else:
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4

    ##PE-IMAGE SECTION HEADER data
    def IMAGE_SETION_HEADER_data(self):
        global Qdata
        Image_file = ["DWORD    Name;    .data","DWORD    ","DWORD    Virtual Size;","DWORD    RVA;",
                      "DWORD    Size of Raw Data;","DWORD    Pointer to Raw Data;","DWORD    Pointer to Relocations;",
                      "DWORD    Pointer to Line Numbers;","WORD    Number of Relocations;","WORD    Number of Line Number;",
                      "DWORD    Characteristics;"]
        lib = self.data
        hex_code = lib.encode('hex')
        print("================================PEfile View================================")
        print '%-15s' % "Offset(h)  Data %9s %8s" % ("Byte", "Value")
        seting = 1
        Header_list = Image_file
        i = 536
        offset = 536
        while (1):
            count = 0
            if (Header_list[0][0] == "W"):
                output_list = Header_list.pop(0)
                if (i == 212):
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력 부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
                else:
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
            elif(Header_list[0][0] == "B"):
                output_list = Header_list.pop(0)
                # 리틀 엔디언 적용하기
                row = 0
                output_endian = ""
                endian_data = hex_code[i * 2:(i + 1) * 2]
                endian = []
                while (row < 8):
                    endian.append(endian_data[row:row + 2])
                    row += 2
                row = 0
                endian.reverse()
                while (row < 4):
                    output_endian += endian.pop(0)
                    row += 1
                print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                offset += 1
                i += 1
            elif(Header_list[0][0] == "I"):
                DATA_list = ["RVA   EXPORT Table","Size","RVA   IMPORT Table","Size","RVA   RESOURCE Table",
                             "Size", "RVA   EXCEPTION Table","Size","RVA   CERTUFUCATE Table","Size","RVA   BASE RELOCATION Table",
                             "Size", "RVA   DEBUG Directroy","Size","RVA   Architecture Specific Data",
                             "Size", "RVA   GLOBAL POINTER Register","Size","RVA   TLS Table","Size",
                             "RVA   LOAD CONFIGURATION Table","Size","RVA   BOUND IMPORT Table","Size",
                             "RVA   IMPORT Address Table","Size","RVA   DELAY IMPORT Descriptors","Size","RVA   CLI Header",
                             "Size","RVA  ","Size"]
                print("-"*80)
                count = 0
                while(1):
                    output_list = DATA_list.pop(0)
                    if(output_list[0]=="R"):
                    # 리틀 엔디언 적용하기
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    else:
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    count += 1
                    if(count%2==0):
                        print("-" * 80)
            else:
                if(Header_list[0] == "DWORD    Pointer to Raw Data;"):
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    a = output_endian
                    Qdata = int(a, 16)
                else:
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4

    ##PE-IMAGE SECTION HEADER idata
    def IMAGE_SETION_HEADER_idata(self):
        global Qidata
        Image_file = ["DWORD    Name;    .idata","DWORD    ","DWORD    Virtual Size;","DWORD    RVA;",
                      "DWORD    Size of Raw Data;","DWORD    Pointer to Raw Data;","DWORD    Pointer to Relocations;",
                      "DWORD    Pointer to Line Numbers;","WORD    Number of Relocations;","WORD    Number of Line Number;",
                      "DWORD    Characteristics;"]
        lib = self.data
        hex_code = lib.encode('hex')
        print("================================PEfile View================================")
        print '%-15s' % "Offset(h)  Data %9s %8s" % ("Byte", "Value")
        seting = 1
        Header_list = Image_file
        i = 576
        offset = 576
        while (1):
            count = 0
            if (Header_list[0][0] == "W"):
                output_list = Header_list.pop(0)
                if (i == 212):
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력 부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
                else:
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
            elif(Header_list[0][0] == "B"):
                output_list = Header_list.pop(0)
                # 리틀 엔디언 적용하기
                row = 0
                output_endian = ""
                endian_data = hex_code[i * 2:(i + 1) * 2]
                endian = []
                while (row < 8):
                    endian.append(endian_data[row:row + 2])
                    row += 2
                row = 0
                endian.reverse()
                while (row < 4):
                    output_endian += endian.pop(0)
                    row += 1
                print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                offset += 1
                i += 1
            elif(Header_list[0][0] == "I"):
                DATA_list = ["RVA   EXPORT Table","Size","RVA   IMPORT Table","Size","RVA   RESOURCE Table",
                             "Size", "RVA   EXCEPTION Table","Size","RVA   CERTUFUCATE Table","Size","RVA   BASE RELOCATION Table",
                             "Size", "RVA   DEBUG Directroy","Size","RVA   Architecture Specific Data",
                             "Size", "RVA   GLOBAL POINTER Register","Size","RVA   TLS Table","Size",
                             "RVA   LOAD CONFIGURATION Table","Size","RVA   BOUND IMPORT Table","Size",
                             "RVA   IMPORT Address Table","Size","RVA   DELAY IMPORT Descriptors","Size","RVA   CLI Header",
                             "Size","RVA  ","Size"]
                print("-"*80)
                count = 0
                while(1):
                    output_list = DATA_list.pop(0)
                    if(output_list[0]=="R"):
                    # 리틀 엔디언 적용하기
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    else:
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    count += 1
                    if(count%2==0):
                        print("-" * 80)
            else:
                if(Header_list[0] == "DWORD    Pointer to Raw Data;"):
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    a = output_endian
                    Qidata = int(a, 16)
                else:
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4

    ##PE-IMAGE SECTION HEADER reloc
    def IMAGE_SETION_HEADER_reloc(self):
        global Qreloc
        Image_file = ["DWORD    Name;    .reloc","DWORD    ","DWORD    Virtual Size;","DWORD    RVA;",
                      "DWORD    Size of Raw Data;","DWORD    Pointer to Raw Data;","DWORD    Pointer to Relocations;",
                      "DWORD    Pointer to Line Numbers;","WORD    Number of Relocations;","WORD    Number of Line Number;",
                      "DWORD    Characteristics;"]
        lib = self.data
        hex_code = lib.encode('hex')
        print("================================PEfile View================================")
        print '%-15s' % "Offset(h)  Data %9s %8s" % ("Byte", "Value")
        seting = 1
        Header_list = Image_file
        i = 616
        offset = 616
        while (1):
            count = 0
            if (Header_list[0][0] == "W"):
                output_list = Header_list.pop(0)
                if (i == 212):
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력 부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
                else:
                    # 리틀 엔디언 적용
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 4):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    endian.reverse()
                    row = 0
                    while (row < 2):
                        output_endian += endian.pop(0)
                        row += 1
                    # 출력부분
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 2
                    i += 2
            elif(Header_list[0][0] == "B"):
                output_list = Header_list.pop(0)
                # 리틀 엔디언 적용하기
                row = 0
                output_endian = ""
                endian_data = hex_code[i * 2:(i + 1) * 2]
                endian = []
                while (row < 8):
                    endian.append(endian_data[row:row + 2])
                    row += 2
                row = 0
                endian.reverse()
                while (row < 4):
                    output_endian += endian.pop(0)
                    row += 1
                print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                offset += 1
                i += 1
            elif(Header_list[0][0] == "I"):
                DATA_list = ["RVA   EXPORT Table","Size","RVA   IMPORT Table","Size","RVA   RESOURCE Table",
                             "Size", "RVA   EXCEPTION Table","Size","RVA   CERTUFUCATE Table","Size","RVA   BASE RELOCATION Table",
                             "Size", "RVA   DEBUG Directroy","Size","RVA   Architecture Specific Data",
                             "Size", "RVA   GLOBAL POINTER Register","Size","RVA   TLS Table","Size",
                             "RVA   LOAD CONFIGURATION Table","Size","RVA   BOUND IMPORT Table","Size",
                             "RVA   IMPORT Address Table","Size","RVA   DELAY IMPORT Descriptors","Size","RVA   CLI Header",
                             "Size","RVA  ","Size"]
                print("-"*80)
                count = 0
                while(1):
                    output_list = DATA_list.pop(0)
                    if(output_list[0]=="R"):
                    # 리틀 엔디언 적용하기
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    else:
                        row = 0
                        output_endian = ""
                        endian_data = hex_code[i * 2:(i + 4) * 2]
                        endian = []
                        while (row < 8):
                            endian.append(endian_data[row:row + 2])
                            row += 2
                        row = 0
                        endian.reverse()
                        while (row < 4):
                            output_endian += endian.pop(0)
                            row += 1
                        print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    count += 1
                    if(count%2==0):
                        print("-" * 80)
            else:
                if(Header_list[0] == "DWORD    Pointer to Raw Data;"):
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4
                    a = output_endian
                    Qreloc = int(a, 16)
                else:
                    output_list = Header_list.pop(0)
                    # 리틀 엔디언 적용하기
                    row = 0
                    output_endian = ""
                    endian_data = hex_code[i * 2:(i + 4) * 2]
                    endian = []
                    while (row < 8):
                        endian.append(endian_data[row:row + 2])
                        row += 2
                    row = 0
                    endian.reverse()
                    while (row < 4):
                        output_endian += endian.pop(0)
                        row += 1
                    print "%.8x   %-10s%s" % (offset, output_endian, output_list)
                    offset += 4
                    i += 4

    ##Hexmod-SETION view
    def Hexmod_SETION(self, on, off):
        lib = self.data
        hex_code = lib.encode('hex')
        offset = on
        print("================================PEfile View================================")
        #옵션 출력
        print '%-15s' % "Offset(h)",
        for i in range(16):
            if (i == 15):
                print "%.2x" % i
            else:
                print "%.2x" % i,
        i = on
        #리드 시작
        while(i<off):
            if (i == 0):
                print"%.8x%10s" % (offset, hex_code[i:i + 2]),
                i += 1
            elif ((i + 1) % 16 == 0):
                print(hex_code[i * 2:(i + 1) * 2])
                offset += 16
                i += 1
            elif ((i + 1) % 16 == 1):
                print "%.8x%10s" % (offset, hex_code[i*2:(i + 1) * 2]),
                i += 1
            else:
                print hex_code[i * 2:(i + 1) * 2],
                i += 1
        print("\n")

    ##Hexmod-SETION_List
    def Hexmod_SETION_List(self, off):
        lib = self.data
        hex_code = lib.encode('hex')
        offset = off
        print("================================PEfile View================================")
        #옵션 출력
        print '%-15s' % "Offset(h)",
        for i in range(16):
            if (i == 15):
                print "%.2x" % i
            else:
                print "%.2x" % i,
        i = off
        #리드 시작
        while(i<off):
            if (i == 0):
                print"%.8x%10s" % (offset, hex_code[i:i + 2]),
                i += 1
            elif ((i + 1) % 16 == 0):
                print(hex_code[i * 2:(i + 1) * 2])
                offset += 16
                i += 1
            elif ((i + 1) % 16 == 1):
                print "%.8x%10s" % (offset, hex_code[i*2:(i + 1) * 2]),
                i += 1
            else:
                print hex_code[i * 2:(i + 1) * 2],
                i += 1
        print("\n")


cal = hander()

if (ex == 1):
    while (1):
        print("%s%s%s" % ("*" * 28, "PE-Viewer&Hex-Edit", "*" * 29))
        try:
            print("Hex-Edit MOD: %24s    PE-view MOD: %s"% ("IMAGE_DOS_HEADER = 1", "SECTION_HEADER text = 8"))
            print("PE-view MOD: %25s    PE-view MOD:%s"% ("IMAGE_DOS_HEADER = 2", "SECTION_HEADER rdata = 9"))
            print("Hex-Edit MOD: %24s    PE-view MOD:%s"% ("DOS_Stub = 3","SECTION_HEADER data = 10"))
            print("Hex-Edit MOD: %24s    PE-view MOD:%s"% ("IMAGE_NT_HEADERS = 4","SECTION_HEADER idata = 11"))
            print("PE-Edit MOD: %25s    PE-view MOD:%s"% ("NT_Signature = 5","SECTION_HEADER reloc = 12"))
            print("PE-Edit MOD: %25s    PE-view MOD:%s"% ("IMAGE_FILE_HEADER = 6","SECTION list view = 13"))
            print("PE-Edit MOD: %25s"% "IMAGE_OPTIONAL_HEADER = 7")
            choice = input("Enter : ")
            if (choice == 1):
                cal.Hexmod_Dos_Header_output()
            elif (choice == 2):
                cal.Dos_Header_output()
            elif (choice == 3):
                cal.Hexmod_Dos_Stub_output()
            elif (choice == 4):
                cal.Hexmod_NT_Headers_output()
            elif (choice == 5):
                cal.NT_Headers_output()
            elif (choice == 6):
                cal.IMAGE_FILE_HEADER_output()
            elif (choice == 7):
                cal.IMAGE_OPTIONAL_HEADER()
            elif (choice == 8):
                cal.IMAGE_SETION_HEADER_text()
            elif (choice == 9):
                cal.IMAGE_SETION_HEADER_rdata()
            elif (choice == 10):
                cal.IMAGE_SETION_HEADER_data()
            elif (choice == 11):
                cal.IMAGE_SETION_HEADER_idata()
            elif (choice == 12):
                cal.IMAGE_SETION_HEADER_reloc()
            elif (choice == 13):
                try:
                    print("%sIMAGE_SECTION_HEADER%s"% ("="*20, "="*20))
                    print("SECTION text : 1")
                    print("SECTION rdata : 2")
                    print("SECTION data : 3")
                    print("SECTION idata : 4")
                    print("SECTION reloc : 5")
                    Schoice = input("Enter : ")
                    if(Schoice == 1):
                        cal.Hexmod_SETION(Qtext, Qrdata)
                    elif(Schoice == 2):
                        cal.Hexmod_SETION(Qrdata, Qdata)
                    elif(Schoice == 3):
                        cal.Hexmod_SETION(Qdata, Qidata)
                    elif(Schoice == 4):
                        cal.Hexmod_SETION(Qidata, Qreloc)
                    elif(Schoice == 5):
                        cal.Hexmod_SETION(Qreloc, 151552)
                except:
                    if(Schoice == 1):
                        print("\n※섹션 헤더를 SECTION text와 SECTION rdata 실행시켜 주세요.※\n")
                    elif (Schoice == 2):
                        print("\n※섹션 헤더를 SECTION rdata와 SECTION data 실행시켜 주세요.※\n")
                    elif (Schoice == 3):
                        print("\n※섹션 헤더를 SECTION data와 SECTION idata 실행시켜 주세요.※\n")
                    elif (Schoice == 4):
                        print("\n※섹션 헤더를 SECTION idata와 SECTION reloc 실행시켜 주세요.※\n")
                    elif (Schoice == 5):
                        print("\n※섹션 헤더를 SECTION reloc 실행시켜 주세요.※\n")
                    else:
                        print("\n※지정된 숫자를 입력해주세요.※\n")
            elif (choice == 14):
                pass
        except NameError:
            print("지정된 숫자를 입력해 주세요. \n")
        except:
            pass
    # cal.Dos_Header_output()
else:
    pass

