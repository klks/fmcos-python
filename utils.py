def assert_success(exam, ret):
    """Assert that a response has SW=0x9000 and abort with message otherwise."""
    assert exam.is_success(ret) == True, f"Aborting execution, SW1_SW2 = {bytes_to_hexstr(ret[-2:])}"
    
def assert_failure(exam, ret):
    """Assert that a response is not successful (SW!=0x9000)."""
    assert exam.is_success(ret) == False, f"Aborting execution, SW1_SW2 = {bytes_to_hexstr(ret[-2:])}"

def bytes_to_hexstr(inp):
    """Convert bytes-like to space-separated hex, e.g., b"\x01\x02" -> "01 02"."""
    return ' '.join(format(ch, "02X") for ch in inp)

def strToint16(str):
    """Parse hex string into list of 1-byte ints grouped by two chars per byte.

    Example: "3F00" -> [0x3F, 0x00]
    """
    int16 = []
    sum = 0
    for i16 in str:
        if sum % 2 != 0:
            int16 = int16 + [int(str[sum - 1:sum + 1], base=16)]
        sum = sum + 1
    return int16