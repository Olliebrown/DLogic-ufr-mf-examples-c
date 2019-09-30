#include "../src/ufr.h"
#if __WIN32 || __WIN64
#	include <conio.h>
#	include <windows.h>
#elif linux || __linux__ || __APPLE__
#	define __USE_MISC  1
#	include <unistd.h>
#	include <termios.h>
#	undef __USE_MISC
#else
#	error "Unknown build platform."
#endif

const char hexChars[22] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                         'a', 'b', 'c', 'd', 'e', 'f',
                         'A', 'B', 'C', 'D', 'E', 'F'};

uint32_t auth_mode = 4;
uint8_t auth_key = MIFARE_AUTHENT1A;
uint8_t auth_key_aes;
uint8_t key_index = 0;
uint8_t PK_CRYPTO1_key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint8_t PK_AES_key[16] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
bool sam_used = false;


#if linux || __linux__ || __APPLE__

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>

static struct termios old;

int _kbhit(void)
{
    int byteswaiting;
    ioctl(0, FIONREAD, &byteswaiting);
    return byteswaiting > 0;
}

void _resetTermios(void)
{
	tcsetattr(0, TCSANOW, &old);
}

char _getch(void)
{
	return getchar();
}

#endif


void ConvertStringToUint8Array(std::string str, uint8_t *array)
{
    for(uint32_t i = 0; i < str.length(); i++)
    {
        char x = str.at(i);
        array[i] = (int)x;
    }
}

bool isCardMifarePlus()
{
    UFR_STATUS status;
    uint8_t card_type;

    status = GetDlogicCardType(&card_type);

    if(!status)
    {
        if(card_type == DL_MIFARE_PLUS_S_2K_SL3 || card_type == DL_MIFARE_PLUS_X_2K_SL3
           || card_type == DL_MIFARE_PLUS_EV1_2K_SL3 || card_type == DL_MIFARE_PLUS_S_4K_SL3
           || card_type == DL_MIFARE_PLUS_X_4K_SL3 || card_type == DL_MIFARE_PLUS_EV1_4K_SL3)
        {
            if(auth_key == MIFARE_AUTHENT1A)
            {
                auth_key_aes = MIFARE_PLUS_AES_AUTHENT1A;
            }
            else if(auth_key == MIFARE_AUTHENT1B)
            {
                auth_key_aes = MIFARE_PLUS_AES_AUTHENT1B;
            }

            return true;
        }
        else
        {
            if(auth_key == MIFARE_PLUS_AES_AUTHENT1A)
            {
                auth_key = MIFARE_AUTHENT1A;
            }
            else if(auth_key == MIFARE_PLUS_AES_AUTHENT1B)
            {
                auth_key = MIFARE_AUTHENT1B;
            }
            return false;
        }
    }
    else
    {
        return false;
    }
}

bool open_sam(void)
{
	UFR_STATUS status;
	uint8_t atr_data[50];
	uint8_t len = 50;

	status = open_ISO7816_interface(atr_data, &len);
	if(status)
	{
		printf("Error code = %02x\n", status);
		return false;
	}
	else
	{
		printf("SAM opened\n");
		return true;
	}
}

//------------------------------------------------------------------------------
void usage(void)
{
        printCurrentAuthConfig();
		printf("+------------------------------------------------+\n"
			   "|   Block (Read/Write) and Linear (Read/Write)   |\n"
			   "|                 version 1.0                    |\n");
	   cout << "|             DLL version " << GetDllVersionStr() << "                 |\n";
		cout <<"+------------------------------------------------+\n";
		printf("                             For exit, hit escape.\n");
		printf("--------------------------------------------------\n");
		printf(" (1) - Change authentication mode\n"
			   " (2) - Change authentication key\n"
			   " (3) - Change key index\n"
			   " (4) - Change provided key\n"
			   " (5) - Block read\n"
			   " (6) - Block write\n"
			   " (7) - Linear read\n"
			   " (8) - Linear write\n"
			   " (a) - Reader key write (AES)\n"
			   " (b) - Reader key write (CRYPTO 1)\n"
			   " (c) - SAM key write\n");
        printf("--------------------------------------------------\n");
}

bool isHexChar(char c)
{
    for(uint8_t i = 0; i < 22; i++)
    {
        if(c == hexChars[i])
        {
            return true;
        }
    }

    return false;
}

string eraseDelimiters(string hexStr)
{
    for(uint32_t i = 0; i < hexStr.length(); i++)
    {
        if(!isHexChar(hexStr.at(i)))
        {
            hexStr.erase(i, 1);
        }
    }

    return hexStr;
}

void convertStrToByteArray(string str, uint8_t *array) {

    str = eraseDelimiters(str);

    for (unsigned int i = 0; i < str.length() / 2; i++) {

        string part = str.substr(i * 2, 2);

        char str1[32];
        char *ptr;
        strcpy(str1, part.c_str());

        array[i] = strtol(str1, &ptr, 16);

    }
}

string ConvertToHexArray(const uint8_t *data, int len, string delimiter) {

    stringstream ss;
    ss << uppercase << hex;

    for (int i = 0; i < len; i++) {
    	if(data[i] <= 0x0F)
    	{
    		 ss << "0";
    	}
    	 ss << (uint32_t) data[i] << delimiter;
    }
    string result = ss.str();

    if(delimiter != "")
    {
         result = result.substr(0, result.length()-1);
    }

    return result;
}

void changeAuthMode()
{

    string choice = "";
    cout << "Choose new authentication mode: " << endl;
    cout << "1. Reader key" << endl;
    cout << "2. Automatic key mode 1 - AKM1" << endl;
    cout << "3. Automatic key mode 2 - AKM2" << endl;
    cout << "4. Provided key" << endl;
    cout << "5. SAM key" << endl;
    cin >> choice;

    if(choice == "1")
    {
	auth_mode = 1;

    }else if(choice == "2")
    {
 	auth_mode = 2;

    }else if(choice == "3")
    {
	auth_mode = 3;
    }else if(choice == "4")
    {
	auth_mode = 4;

    }
    else if(choice == "5")
    {
        auth_mode = 5;
        if(!sam_used)
        {
            if(open_sam())
                sam_used = true;
            else
                cout << "Error during SAM open" << endl;
        }
    }
    else
    {
	cout << "Wrong input, enter number from 1 - 4" << endl;
    }

    fflush(stdin);
}

void changeAuthenticationKey()
{
    string key_for_auth;
    cout << "Choose new authentication key: " << endl;
    cout << "1. KEY A" << endl;
    cout << "2. KEY B" << endl;
    cin >> key_for_auth;

    if(key_for_auth == "1")
    {
	auth_key = MIFARE_AUTHENT1A;
    }
    else if(key_for_auth == "2")
    {
	auth_key = MIFARE_AUTHENT1B;
    }
    else
    {
	cout << "Wrong input enter 1 for KEY A or 2 for KEY B" << endl;
    }

    fflush(stdin);
}

void changeKeyIndex()
{
    uint32_t index = 0;
    cout << "Enter new key index (0 - 31 for reader) (1 - 127 for SAM) : " << endl;
    scanf("%d", &index);

    if(index < 0 || index > 127)
    {
        cout << "Wrong input (key index are from 0 - 127)" << endl;
    }
    else
    {
        key_index = index;
    }
    fflush(stdin);
}

void changeProvidedKey()
{
    int choice;
    cout << "What key do you want to change?" << endl;
    cout << "1. Provided key (CRYPTO 1 key)" << endl;
    cout << "2. Provided key (AES key)" << endl;
    scanf("%d%*c", &choice);
    fflush(stdin);
    string new_key = "";

    if(choice == 1)
    {
	    cout << "Enter new provided CRYPTO 1 key (6 bytes) with any delimiter:" << endl;
            getline(cin, new_key);

            new_key = eraseDelimiters(new_key);

            if(new_key.length() != 12)
            {
                cout << "Key must be 6 bytes long" << endl;
            }
            else
            {
                convertStrToByteArray(new_key, PK_CRYPTO1_key);
            }
            fflush(stdin);
    }
    else if(choice == 2)
    {
    	cout << "Enter new provided AES key (16 bytes) with any delimiter:" << endl;
            getline(cin, new_key);

            new_key = eraseDelimiters(new_key);

            if(new_key.length() != 32)
            {
                cout << "Key must be 16 bytes long" << endl;
            }
            else
            {
                convertStrToByteArray(new_key, PK_AES_key);
            }
            fflush(stdin);
    }
    else
    {
	cout << "Wrong input, choose 1 or 2" << endl;
    }

    fflush(stdin);
}

void operation_BlockRead()
{
    UFR_STATUS status;
    uint32_t address = 0;
    uint8_t block_address = 0;
    uint8_t data[16];

    cout << "Enter block address you want to read" << endl;
    scanf("%d", &address);

    if(address > 255)
    {
        cout << "Invalid block address" << endl;
        return;
    }

    block_address = address;

    uint8_t KEY[16];
    memset(KEY, 0xFF, 16);

    status = UFR_OK;

    switch(auth_mode)
    {
        case 1:
            status = BlockRead(data, block_address, auth_key, key_index);
            break;
        case 2:
            status = BlockRead_AKM1(data, block_address, auth_key);
            break;
        case 3:
            status = BlockRead_AKM2(data, block_address, auth_key);
            break;
        case 4:
            if(isCardMifarePlus())
            {
                status = BlockRead_PK(data, block_address, auth_key_aes, PK_AES_key);
            }
            else
            {
                status = BlockRead_PK(data, block_address, auth_key, PK_CRYPTO1_key);
            }
            break;
        case 5:
            status = BlockReadSamKey(data, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Block " << (int)block_address << " data :" << endl;
        cout << ConvertToHexArray(data, 16, " ") << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_BlockWrite()
{
    UFR_STATUS status = UFR_WRITING_ERROR;
    uint32_t address = 0;
    uint8_t block_address = 0;
    uint8_t data[16];
    string blockdataStr = "";

    cout << "Enter block address you want to write" << endl;
    scanf("%d%*c", &address);
    fflush(stdin);

    if(address > 255)
    {
        cout << "Invalid block address" << endl;
        return;
    }

    block_address = address;


    cout << "Enter block data (16 bytes hex) with any delimiter:" << endl;
    getline(cin, blockdataStr);
    fflush(stdin);

    blockdataStr = eraseDelimiters(blockdataStr);

    if(blockdataStr.length() != 32)
    {
        cout << "Block data must be 16 bytes long" << endl;
        return;
    }

    convertStrToByteArray(blockdataStr, data);

    switch(auth_mode)
    {
        case 1:
            status = BlockWrite(data, block_address, auth_key, key_index);
            break;
        case 2:
            status = BlockWrite_AKM1(data, block_address, auth_key);
            break;
        case 3:
            status = BlockWrite_AKM2(data, block_address, auth_key);
            break;
        case 4:

            if(isCardMifarePlus())
            {
                status = BlockWrite_PK(data, block_address, auth_key_aes, PK_AES_key);
            }
            else
            {
                status = BlockWrite_PK(data, block_address, auth_key, PK_CRYPTO1_key);
            }
            break;
        case 5:
            status = BlockWriteSamKey(data, block_address, auth_key, key_index);
    }

    if(!status)
    {
        cout << "Block " << (int)block_address << " successfully written" << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_LinearRead()
{
    UFR_STATUS status = UFR_READING_ERROR;
    uint8_t data[8192];
    uint16_t linear_addr;
    uint16_t data_length;
    uint16_t bytes_returned;

    uint32_t address;
    uint32_t length_bytes;

    cout << "Enter linear address (where to start reading):" << endl;
    scanf("%d%*c", &address);
    fflush(stdin);
    cout << "Enter how many bytes to read:" << endl;
    scanf("%d%*c", &length_bytes);
    fflush(stdin);

    linear_addr = address;
    data_length = length_bytes;

    switch(auth_mode)
    {
        case 1:
            status = LinearRead(data, linear_addr, data_length, &bytes_returned, auth_key, key_index);
            break;

        case 2:
            status = LinearRead_AKM1(data, linear_addr, data_length, &bytes_returned, auth_key);
            break;

        case 3:
            status = LinearRead_AKM2(data, linear_addr, data_length, &bytes_returned, auth_key);
            break;

        case 4:

            if(isCardMifarePlus())
            {
                status = LinearRead_PK(data, linear_addr, data_length, &bytes_returned, auth_key, PK_AES_key);
            }
            else
            {
                status = LinearRead_PK(data, linear_addr, data_length, &bytes_returned, auth_key, PK_CRYPTO1_key);
            }
            break;

        case 5:
            status = LinearReadSamKey(data, linear_addr, data_length, &bytes_returned, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Data[" << (int)bytes_returned << " bytes]:" << endl;
        cout << ConvertToHexArray(data, (int)bytes_returned, " ") << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_LinearWrite()
{
    UFR_STATUS status = UFR_WRITING_ERROR;
    uint8_t data[8192];
    uint16_t linear_addr;
    uint16_t data_length;
    uint16_t bytes_written;

    uint32_t address;
    string dataStr = "";

    cout << "Enter linear address (where to start writing):" << endl;
    scanf("%d%*c", &address);
    fflush(stdin);

    linear_addr = address;

    cout << "Enter data (hex bytes with any delimiter):" << endl;
    getline(cin, dataStr);
    fflush(stdin);

    dataStr = eraseDelimiters(dataStr);

    if(dataStr.length() % 2 != 0)
    {
        cout << "Invalid input, data must contain pairs of hex bytes" << endl;
        return;
    }

    data_length = dataStr.length() / 2;
    convertStrToByteArray(dataStr, data);

    switch(auth_mode)
    {
        case 1:
            status = LinearWrite(data, linear_addr, data_length, &bytes_written, auth_key, key_index);
            break;

        case 2:
            status = LinearWrite_AKM1(data, linear_addr, data_length, &bytes_written, auth_key);
            break;

        case 3:
            status = LinearWrite_AKM2(data, linear_addr, data_length, &bytes_written, auth_key);
            break;

        case 4:
            if(isCardMifarePlus())
            {
                status = LinearWrite_PK(data, linear_addr, data_length, &bytes_written, auth_key, PK_AES_key);
            }
            else
            {
                status = LinearWrite_PK(data, linear_addr, data_length, &bytes_written, auth_key, PK_CRYPTO1_key);
            }
            break;

        case 5:
            status = LinearWriteSamKey(data, linear_addr, data_length, &bytes_written, auth_key, key_index);
            break;

    }

    if(!status)
    {
        cout << "Data [" << (int)data_length << " bytes] successfully written" << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void printCurrentAuthConfig()
{
    stringstream conf;
    string curr_auth_mode = "";
    string auth_key_str = "";
    string key_index_str = "";

    switch(auth_mode)
    {
        case 1:
            curr_auth_mode = "Reader key";
            break;
        case 2:
            curr_auth_mode = "Automatic key mode - AKM1";
            break;
        case 3:
            curr_auth_mode = "Automatic key mode - AKM2";
            break;
        case 4:
            curr_auth_mode = "Provided key";
            break;
        case 5:
            curr_auth_mode = "SAM key";
    }

    switch(auth_key)
    {
        case MIFARE_AUTHENT1A:
        case MIFARE_PLUS_AES_AUTHENT1A:
            auth_key_str = "KEY A";
            break;
        case MIFARE_AUTHENT1B:
        case MIFARE_PLUS_AES_AUTHENT1B:
            auth_key_str = "KEY B";
            break;
    }

    conf << "Authentication mode : " << curr_auth_mode << endl;
    conf << "Authentication key : " << auth_key_str << endl;
    conf << "Key index : " << to_string(key_index) << endl;
    conf << "Provided key (CRYPTO 1): " << ConvertToHexArray(PK_CRYPTO1_key, 6, " ") << endl;
    conf << "Provided key (AES key): " << ConvertToHexArray(PK_AES_key, 16, " ") << endl;

    cout << conf.str() << endl;
}

void operation_ReaderKeyWrite()
{
    UFR_STATUS status;
    uint8_t reader_key[6];
    uint8_t reader_key_index;
    string rk_str = "";
    uint32_t rk_index;

    cout << "Enter key index in the reader you want to write:" << endl;
    scanf("%d%*c", &rk_index);

    fflush(stdin);
    cout << "Enter new key (6 bytes hex) with any delimiter:" << endl;
    getline(cin, rk_str);

    rk_str = eraseDelimiters(rk_str);

    if(rk_str.length() != 12)
    {
        cout << "Key must be 6 bytes long" << endl;
        return;
    }

    reader_key_index = rk_index;
    convertStrToByteArray(rk_str, reader_key);

    status = ReaderKeyWrite(reader_key, reader_key_index);

    if(!status)
    {
        cout << "CRYPTO 1 key at index " << (int)reader_key_index << " successfully written into reader" << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_ReaderKeyWriteAes()
{
    UFR_STATUS status;
    uint8_t reader_key[16];
    uint8_t reader_key_index;
    string rk_str = "";
    uint32_t rk_index;

    cout << "Enter key index in the reader you want to write:" << endl;
    scanf("%d%*c", &rk_index);

    fflush(stdin);
    cout << "Enter new key (16 bytes hex) with any delimiter:" << endl;
    getline(cin, rk_str);

    rk_str = eraseDelimiters(rk_str);

    if(rk_str.length() != 32)
    {
        cout << "Key must be 16 bytes long" << endl;
        return;
    }

    reader_key_index = rk_index;
    convertStrToByteArray(rk_str, reader_key);

    status = uFR_int_DesfireWriteAesKey(reader_key_index, reader_key);

    if(!status)
    {
        cout << "AES key at index " << (int)reader_key_index << " successfully written into reader" << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_SamKeyWrite(void)
{
    UFR_STATUS status;
    int key_no_int, key_ver_int;
    string key_str = "";
    uint8_t card_key[16];
    uint8_t key_a[6], key_b[6];
    uint8_t master_key[16], master_key_ver;
    uint8_t apdu_sw[2];
    uint8_t auth_key_no;
    char key;

   	if(!sam_used)
	{
		if(open_sam())
			sam_used = true;
		else
		{
			printf("Error during SAM open \n");
			return;
		}
	}

    cout << " Enter SAM card key type" << endl;
	cout << " (1) - SAM CRYPTO1 key" << endl;
    cout << " (2) - SAM AES key" << endl;

    while (!_kbhit())
		;
	key = _getch();

	if(key == '1')
    {
        fflush(stdin);
        cout << "Enter CRYPTO1 key A (6 bytes hex) with any delimiter:" << endl;
        getline(cin, key_str);

        key_str = eraseDelimiters(key_str);

        if(key_str.length() != 12)
        {
            cout << "Key must be 6 bytes long" << endl;
            return;
        }

        convertStrToByteArray(key_str, key_a);

        fflush(stdin);
        cout << "Enter CRYPTO1 key B (6 bytes hex) with any delimiter:" << endl;
        getline(cin, key_str);

        key_str = eraseDelimiters(key_str);

        if(key_str.length() != 12)
        {
            cout << "Key must be 6 bytes long" << endl;
            return;
        }

        convertStrToByteArray(key_str, key_b);
    }
    else if(key == '2')
    {
        fflush(stdin);
        cout << "Enter AES key (16 bytes hex) with any delimiter:" << endl;
        getline(cin, key_str);

        key_str = eraseDelimiters(key_str);

        if(key_str.length() != 32)
        {
            cout << "Key must be 16 bytes long" << endl;
            return;
        }

        convertStrToByteArray(key_str, card_key);
    }
    else
    {
        cout << "Wrong choice" << endl;
        return;
    }

    cout << "Enter SAM ordinal key number (0 - 127):" << endl;
    scanf("%d%*c", &key_no_int);
    key_index = key_no_int & 0xFF;

    cout << "Enter SAM key for host authentication ordinal number:" << endl;
    scanf("%d%*c", &key_no_int);
    auth_key_no = key_no_int & 0x7F;

    cout << "Enter version of host authentication key (0 - 255):" << endl;
    scanf("%d%*c", &key_ver_int);
    master_key_ver = key_ver_int & 0xFF;

    fflush(stdin);
    cout << "Enter AES host key (16 bytes hex) with any delimiter:" << endl;
    getline(cin, key_str);

    key_str = eraseDelimiters(key_str);

    if(key_str.length() != 32)
    {
        cout << "Key must be 16 bytes long" << endl;
        return;
    }

    convertStrToByteArray(key_str, master_key);

    status = SAM_authenticate_host_AV2_plain(master_key, auth_key_no, master_key_ver, apdu_sw);

    if(status)
    {
        cout << "Host authentication error" << endl;
        cout << "Status is " << UFR_Status2String(status) << endl;
        return;
    }
    else
        cout << "Host authentication is OK" << endl;

    if(key == '1')
        status = SAM_change_key_entry_mifare_AV2_plain_one_key(key_index, key_a, key_b, auth_key_no, master_key_ver, 0xFF, apdu_sw);
    else
        status = SAM_change_key_entry_AES_AV2_plain_one_key(key_index, card_key, auth_key_no, auth_key_no, 0xFF, apdu_sw);

    if(status)
    {
        cout << "Change key entry error" << endl;
        cout << "Status is " << UFR_Status2String(status) << endl;
        return;
    }
    else
        cout << "AES card key stored successfully" << endl;
}
