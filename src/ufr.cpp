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
			   "|                 version 1.2                    |\n");
	   cout << "|             DLL version " << GetDllVersionStr() << "                 |\n";
		cout <<"+------------------------------------------------+\n";
		printf("                             For exit, hit escape.\n");
		printf("--------------------------------------------------\n");
		printf(" (1) - Change authentication mode\n"
			   " (2) - Change authentication key\n"
			   " (3) - Change key index\n"
			   " (4) - Change provided key\n"
			   " (5) - Block read\n"
			   " (6) - Block in sector read\n"
			   " (7) - Block write\n"
			   " (8) - Block in sector write\n"
			   " (9) - Linear read\n"
			   " (a) - Linear write\n"
			   " (b) - Value block read\n"
			   " (c) - Value block write\n"
			   " (d) - Value block increment\n"
			   " (e) - Value block decrement\n"
			   " (f) - Value block in sector read\n"
			   " (g) - Value block in sector write\n"
			   " (h) - Value block in sector increment\n"
			   " (i) - Value block in sector decrement\n"
			   " (j) - Sector trailer write\n"
			   " (k) - Reader key write (CRYPTO 1)\n"
			   " (l) - SAM key write\n");
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
    fflush(stdin);
    string new_key = "";

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
            status = BlockRead_PK(data, block_address, auth_key, PK_CRYPTO1_key);
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

void operation_BlockInSectorRead()
{
    UFR_STATUS status;
    uint32_t address = 0;
    uint8_t block_address = 0;
    uint8_t sector_address = 0;
    uint8_t data[16];

    cout << "Enter sector address you want to read:" << endl;
    scanf("%d%*c", &address);

    sector_address = address;

    cout << "Enter block address you want to read:" << endl;
    scanf("%d%*c", &address);

    block_address = address;

    uint8_t KEY[16];
    memset(KEY, 0xFF, 16);

    status = UFR_OK;

    switch(auth_mode)
    {
        case 1:
            status = BlockInSectorRead(data, sector_address, block_address, auth_key, key_index);
            break;
        case 2:
            status = BlockInSectorRead_AKM1(data, sector_address, block_address, auth_key);
            break;
        case 3:
            status = BlockInSectorRead_AKM2(data, sector_address, block_address, auth_key);
            break;
        case 4:
            status = BlockInSectorRead_PK(data, sector_address, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = BlockInSectorReadSamKey(data, sector_address, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Sector " << (int)sector_address << ", block " << (int)block_address << " data :" << endl;
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
            status = BlockWrite_PK(data, block_address, auth_key, PK_CRYPTO1_key);
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

void operation_BlockInSectorWrite()
{
    UFR_STATUS status = UFR_WRITING_ERROR;
    uint32_t address = 0;
    uint8_t sector_address = 0;
    uint8_t block_address = 0;
    uint8_t data[16];
    string blockdataStr = "";

    cout << "Enter sector address you want to write:" << endl;
    scanf("%d%*c", &address);

    sector_address = address;

    cout << "Enter block address you want to write:" << endl;
    scanf("%d%*c", &address);
    fflush(stdin);

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
            status = BlockInSectorWrite(data, sector_address, block_address, auth_key, key_index);
            break;
        case 2:
            status = BlockInSectorWrite_AKM1(data, sector_address, block_address, auth_key);
            break;
        case 3:
            status = BlockInSectorWrite_AKM2(data, sector_address, block_address, auth_key);
            break;
        case 4:
            status = BlockInSectorWrite_PK(data, sector_address, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = BlockInSectorWriteSamKey(data, sector_address, block_address, auth_key, key_index);
    }

    if(!status)
    {
        cout <<"Sector " << (int)sector_address << ", block " << (int)block_address << " successfully written" << endl;
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
            status = LinearRead_PK(data, linear_addr, data_length, &bytes_returned, auth_key, PK_CRYPTO1_key);
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
            status = LinearWrite_PK(data, linear_addr, data_length, &bytes_written, auth_key, PK_CRYPTO1_key);
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
            auth_key_str = "KEY A";
            break;
        case MIFARE_AUTHENT1B:
            auth_key_str = "KEY B";
            break;
    }

    conf << "Authentication mode : " << curr_auth_mode << endl;
    conf << "Authentication key : " << auth_key_str << endl;
    conf << "Key index : " << to_string(key_index) << endl;
    conf << "Provided key (CRYPTO 1): " << ConvertToHexArray(PK_CRYPTO1_key, 6, " ") << endl;

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

void operation_ValueBlockRead()
{
    UFR_STATUS status = UFR_OK;
    uint32_t address = 0;
    uint8_t block_address = 0;
    int32_t value = 0;
    uint8_t value_addr = 0;

    cout << "Enter block address in which you want to read value:" << endl;
    scanf("%d%*c", &address);

    if(address > 255)
    {
        cout << "Invalid block address" << endl;
        return;
    }

    block_address = address;

    switch(auth_mode)
    {
        case 1:
            status = ValueBlockRead(&value, &value_addr, block_address, auth_key, key_index);
            break;
        case 2:
            status = ValueBlockRead_AKM1(&value, &value_addr, block_address, auth_key);
            break;
        case 3:
            status = ValueBlockRead_AKM2(&value, &value_addr, block_address, auth_key);
            break;
        case 4:
            status = ValueBlockRead_PK(&value, &value_addr, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = ValueBlockReadSamKey(&value, &value_addr, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Block " << (int)block_address << " value at address " << (int)value_addr << ":" << endl;
        cout << (int)value << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_ValueBlockWrite()
{
    UFR_STATUS status = UFR_OK;
    uint32_t temp = 0;
    uint8_t block_address = 0;
    int32_t value = 0;
    uint8_t value_addr = 0;

    cout << "Enter block address in which you want to write value:" << endl;
    scanf("%d%*c", &temp);

    block_address = temp;

    cout << "Enter value:" << endl;
    scanf("%d%*c", &temp);

    value = temp;

    cout << "Enter value address:" << endl;
    scanf("%d%*c", &temp);

    value_addr = temp;

    switch(auth_mode)
    {
        case 1:
            status = ValueBlockWrite(value, value_addr, block_address, auth_key, key_index);
            break;
        case 2:
            status = ValueBlockWrite_AKM1(value, value_addr, block_address, auth_key);
            break;
        case 3:
            status = ValueBlockWrite_AKM2(value, value_addr, block_address, auth_key);
            break;
        case 4:
            status = ValueBlockWrite_PK(value, value_addr, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = ValueBlockWriteSamKey(value, value_addr, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Block " << (int)block_address << " value at address " << (int)value_addr << " successfully written." << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_ValueBlockIncrement()
{
    UFR_STATUS status = UFR_OK;
    uint32_t temp = 0;
    uint8_t block_address = 0;
    int32_t value = 0;
    uint8_t value_addr = 0;

    cout << "Enter block address in which you want to increment value:" << endl;
    scanf("%d%*c", &temp);

    block_address = temp;

    cout << "Enter increment value:" << endl;
    scanf("%d%*c", &temp);

    value = temp;

    switch(auth_mode)
    {
        case 1:
            status = ValueBlockIncrement(value, block_address, auth_key, key_index);
            break;
        case 2:
            status = ValueBlockIncrement_AKM1(value, block_address, auth_key);
            break;
        case 3:
            status = ValueBlockIncrement_AKM2(value, block_address, auth_key);
            break;
        case 4:
            status = ValueBlockIncrement_PK(value, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = ValueBlockIncrementSamKey(value, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Block " << (int)block_address << " value at address " << (int)value_addr << " successfully incremented." << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_ValueBlockDecrement()
{
    UFR_STATUS status = UFR_OK;
    uint32_t temp = 0;
    uint8_t block_address = 0;
    int32_t value = 0;
    uint8_t value_addr = 0;

    cout << "Enter block address in which you want to decrement value:" << endl;
    scanf("%d%*c", &temp);

    block_address = temp;

    cout << "Enter decrement value:" << endl;
    scanf("%d%*c", &temp);

    value = temp;

    switch(auth_mode)
    {
        case 1:
            status = ValueBlockDecrement(value, block_address, auth_key, key_index);
            break;
        case 2:
            status = ValueBlockDecrement_AKM1(value, block_address, auth_key);
            break;
        case 3:
            status = ValueBlockDecrement_AKM2(value, block_address, auth_key);
            break;
        case 4:
            status = ValueBlockDecrement_PK(value, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = ValueBlockDecrementSamKey(value, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Block " << (int)block_address << " value at address " << (int)value_addr << " successfully decremented." << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_ValueBlockInSectorRead()
{
    UFR_STATUS status = UFR_WRITING_ERROR;
    uint32_t temp = 0;
    uint8_t sector_address = 0;
    uint8_t block_address = 0;
    int32_t value = 0;
    uint8_t value_addr = 0;

    cout << "Enter sector address in which you want to read value:" << endl;
    scanf("%d%*c", &temp);

    sector_address = temp;

    cout << "Enter block address in which you want to read value:" << endl;
    scanf("%d%*c", &temp);

    block_address = temp;

    switch(auth_mode)
    {
        case 1:
            status = ValueBlockInSectorRead(&value, &value_addr, sector_address, block_address, auth_key, key_index);
            break;
        case 2:
            status = ValueBlockInSectorRead_AKM1(&value, &value_addr, sector_address, block_address, auth_key);
            break;
        case 3:
            status = ValueBlockInSectorRead_AKM2(&value, &value_addr, sector_address, block_address, auth_key);
            break;
        case 4:
            status = ValueBlockInSectorRead_PK(&value, &value_addr, sector_address, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = ValueBlockInSectorReadSamKey(&value, &value_addr, sector_address, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Sector " << (int)sector_address << ", block " << (int)block_address << " value at address " << (int)value_addr << ":" << endl;
        cout << (int)value << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_ValueBlockInSectorWrite()
{
    UFR_STATUS status = UFR_WRITING_ERROR;
    uint32_t temp = 0;
    uint8_t sector_address = 0;
    uint8_t block_address = 0;
    int32_t value = 0;
    uint8_t value_addr = 0;

    cout << "Enter sector address in which you want to write value:" << endl;
    scanf("%d%*c", &temp);

    sector_address = temp;

    cout << "Enter block address in which you want to write value:" << endl;
    scanf("%d%*c", &temp);

    block_address = temp;

    cout << "Enter value:" << endl;
    scanf("%d%*c", &temp);

    value = temp;

    cout << "Enter value address:" << endl;
    scanf("%d%*c", &temp);

    value_addr = temp;

    switch(auth_mode)
    {
        case 1:
            status = ValueBlockInSectorWrite(value, value_addr, sector_address, block_address, auth_key, key_index);
            break;
        case 2:
            status = ValueBlockInSectorWrite_AKM1(value, value_addr, sector_address, block_address, auth_key);
            break;
        case 3:
            status = ValueBlockInSectorWrite_AKM2(value, value_addr, sector_address, block_address, auth_key);
            break;
        case 4:
            status = ValueBlockInSectorWrite_PK(value, value_addr, sector_address, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = ValueBlockInSectorWriteSamKey(value, value_addr, sector_address, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Sector " << (int)sector_address << ", block " << (int)block_address << " value at address " << (int)value_addr << " successfully written." << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_ValueBlockInSectorIncrement()
{
    UFR_STATUS status = UFR_WRITING_ERROR;
    uint32_t temp = 0;
    uint8_t sector_address = 0;
    uint8_t block_address = 0;
    int32_t value = 0;
    uint8_t value_addr = 0;

    cout << "Enter sector address in which you want to increment value:" << endl;
    scanf("%d%*c", &temp);

    sector_address = temp;

    cout << "Enter block address in which you want to increment value:" << endl;
    scanf("%d%*c", &temp);

    block_address = temp;

    cout << "Enter increment value:" << endl;
    scanf("%d%*c", &temp);

    value = temp;

    value_addr = temp;

    switch(auth_mode)
    {
        case 1:
            status = ValueBlockInSectorIncrement(value, sector_address, block_address, auth_key, key_index);
            break;
        case 2:
            status = ValueBlockInSectorIncrement_AKM1(value, sector_address, block_address, auth_key);
            break;
        case 3:
            status = ValueBlockInSectorIncrement_AKM2(value, sector_address, block_address, auth_key);
            break;
        case 4:
            status = ValueBlockInSectorIncrement_PK(value, sector_address, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = ValueBlockInSectorIncrementSamKey(value, sector_address, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Sector " << (int)sector_address << ", block " << (int)block_address << " value at address " << (int)value_addr << " successfully incremented." << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_ValueBlockInSectorDecrement()
{
    UFR_STATUS status = UFR_WRITING_ERROR;
    uint32_t temp = 0;
    uint8_t sector_address = 0;
    uint8_t block_address = 0;
    int32_t value = 0;
    uint8_t value_addr = 0;

    cout << "Enter sector address in which you want to decrement value:" << endl;
    scanf("%d%*c", &temp);

    sector_address = temp;

    cout << "Enter block address in which you want to decrement value:" << endl;
    scanf("%d%*c", &temp);

    block_address = temp;

    cout << "Enter decrement value:" << endl;
    scanf("%d%*c", &temp);

    value = temp;

    value_addr = temp;

    switch(auth_mode)
    {
        case 1:
            status = ValueBlockInSectorDecrement(value, sector_address, block_address, auth_key, key_index);
            break;
        case 2:
            status = ValueBlockInSectorDecrement_AKM1(value, sector_address, block_address, auth_key);
            break;
        case 3:
            status = ValueBlockInSectorDecrement_AKM2(value, sector_address, block_address, auth_key);
            break;
        case 4:
            status = ValueBlockInSectorDecrement_PK(value, sector_address, block_address, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = ValueBlockInSectorDecrementSamKey(value, sector_address, block_address, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Sector " << (int)sector_address << ", block " << (int)block_address << " value at address " << (int)value_addr << " successfully decremented." << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}

void operation_SectorTrailerWrite()
{
    UFR_STATUS status = UFR_OK;
    uint8_t addressing_mode;
    uint8_t address = 0;
    uint8_t new_key_A[6];
    uint8_t block0_access_bits = 0;
    uint8_t block1_access_bits = 0;
    uint8_t block2_access_bits = 0;
    uint8_t sector_trailer_access_bits = 0;
    uint8_t sector_trailer_byte9 = 0;
    uint8_t new_key_B[6];
    uint32_t temp = 0;
    string key_str = "";

    cout << "Choose addressing mode:" << endl;
    cout << "1. Absolute     2. Relative" << endl;
    scanf("%d%*c", &temp);

    addressing_mode = temp - 1;

    cout << "Enter sector trailer address:" << endl;
    scanf("%d%*c", &temp);

    address = temp;

    cout << "Enter block 0 access bits:" << endl;
    scanf("%d%*c", &temp);

    block0_access_bits = temp;

    cout << "Enter block 1 access bits:" << endl;
    scanf("%d%*c", &temp);

    block1_access_bits = temp;

    cout << "Enter block 2 access bits:" << endl;
    scanf("%d%*c", &temp);

    block2_access_bits = temp;

    cout << "Enter sector trailer access bits:" << endl;
    scanf("%d%*c", &temp);

    sector_trailer_access_bits = temp;

    cout << "Enter sector trailer byte 9:" << endl;
    scanf("%d%*c", &temp);

    sector_trailer_byte9 = temp;

    cout << "Enter new key A:" << endl;
    getline(cin, key_str);
    key_str = eraseDelimiters(key_str);
    fflush(stdin);

    if(key_str.length() != 12)
    {
        cout << "Key A must be 6 bytes long" << endl;
        return;
    }

    convertStrToByteArray(key_str, new_key_A);

    key_str = "";

    cout << "Enter new key B:" << endl;
    getline(cin, key_str);
    key_str = eraseDelimiters(key_str);
    fflush(stdin);

    if(key_str.length() != 12)
    {
        cout << "Key B must be 6 bytes long" << endl;
        return;
    }

    convertStrToByteArray(key_str, new_key_B);

    switch(auth_mode)
    {
        case 1:
            status = SectorTrailerWrite(addressing_mode, address, new_key_A, block0_access_bits, block1_access_bits, block2_access_bits, sector_trailer_access_bits, sector_trailer_byte9,
                                        new_key_B, auth_key, key_index);
            break;
        case 2:
            status = SectorTrailerWrite_AKM1(addressing_mode, address, new_key_A, block0_access_bits, block1_access_bits, block2_access_bits, sector_trailer_access_bits, sector_trailer_byte9,
                                        new_key_B, auth_key);
            break;
        case 3:
            status = SectorTrailerWrite_AKM2(addressing_mode, address, new_key_A, block0_access_bits, block1_access_bits, block2_access_bits, sector_trailer_access_bits, sector_trailer_byte9,
                                        new_key_B, auth_key);
            break;
        case 4:
            status = SectorTrailerWrite_PK(addressing_mode, address, new_key_A, block0_access_bits, block1_access_bits, block2_access_bits, sector_trailer_access_bits, sector_trailer_byte9,
                                        new_key_B, auth_key, PK_CRYPTO1_key);
            break;
        case 5:
            status = SectorTrailerWriteSamKey(addressing_mode, address, new_key_A, block0_access_bits, block1_access_bits, block2_access_bits, sector_trailer_access_bits, sector_trailer_byte9,
                                        new_key_B, auth_key, key_index);
            break;
    }

    if(!status)
    {
        cout << "Sector " << (int)address << " successfully written." << endl;
    }
    else
    {
        cout << "Error, status is " << UFR_Status2String(status) << endl;
    }
}
