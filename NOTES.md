FMCOS Information
=================

#Access rights table
#|================================================================================|
#| b08 | b07 | b06 | b05 | b04 | b03 | b02 | b01 |             Notes              |
#|================================================================================|
#|  1  |  -  |  -  |  -  |  -  |  -  |  -  |  -  |   MAC/Encryption Not Required  |
#|  0  |  -  |  -  |  -  |  -  |  -  |  -  |  -  |     MAC/Encryption Required    |
#|  -  |  1  |  1  |  1  |  -  |  -  |  -  |  -  |            Reserved            |
#|=================================================================================
#|  -  |  -  |  -  |  -  |  1  |  1  |  -  |  -  | =============== | Use Key ID 0 |
#|  -  |  -  |  -  |  -  |  1  |  0  |  -  |  -  | |     Read    | | Use Key ID 1 |
#|  -  |  -  |  -  |  -  |  0  |  1  |  -  |  -  | | Permissions | | Use Key ID 2 |
#|  -  |  -  |  -  |  -  |  0  |  0  |  -  |  -  | =============== | Use Key ID 3 |
#|=================================================================================
#|  -  |  -  |  -  |  -  |  -  |  -  |  1  |  1  | ==============  | Use Key ID 0 |
#|  -  |  -  |  -  |  -  |  -  |  -  |  1  |  0  | |    Write    | | Use Key ID 1 |
#|  -  |  -  |  -  |  -  |  -  |  -  |  0  |  1  | | Permissions | | Use Key ID 2 |
#|  -  |  -  |  -  |  -  |  -  |  -  |  0  |  0  | ==============  | Use Key ID 3 |
#|=================================================================================


#Record
#|======================================================================================|
#| b08 | b07 | b06 | b05 | b04 | b03 | b02 | b01 |                 Notes                |
#|======================================================================================|
#|  X  |  X  |  X  |  X  |  X  |  -  |  -  |  -  |   File Identifier (Non-Zero Values)  |
#|  0  |  0  |  0  |  0  |  0  |  -  |  -  |  -  |   Use Current File                   |
#|  0  |  -  |  -  |  -  |  -  |  1  |  0  |  0  |   Use value in P1                    |
#|  0  |  -  |  -  |  -  |  -  |  0  |  0  |  0  |   P1 points to first record marked   |
#|  0  |  -  |  -  |  -  |  -  |  0  |  0  |  1  |   P1 points to last record marked    |
#|  0  |  -  |  -  |  -  |  -  |  0  |  1  |  0  |   P1 points to next record marked    |
#|  0  |  -  |  -  |  -  |  -  |  0  |  1  |  1  |   P1 points to prev record marked    |
#|======================================================================================|