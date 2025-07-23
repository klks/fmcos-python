def assert_success(exam, ret):
    assert exam.is_success(ret) == True, f"Aborting execution, SW1_SW2 = {bytes_to_hexstr(ret[-2:])}"
    
def assert_failure(exam, ret):
    assert exam.is_success(ret) == False, f"Aborting execution, SW1_SW2 = {bytes_to_hexstr(ret[-2:])}"

def bytes_to_hexstr(inp):
    return ' '.join(format(ch, "02X") for ch in inp)

def strToint16(str):
    int16 = []
    sum = 0
    for i16 in str:
        if sum % 2 != 0:
            int16 = int16 + [int(str[sum - 1:sum + 1], base=16)]
        sum = sum + 1
    return int16