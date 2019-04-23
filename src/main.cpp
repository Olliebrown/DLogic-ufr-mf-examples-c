#include <iostream>
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
#include "../src/ufr.h"

#define APP_VERSION	 "1.0"

using namespace std;

void usage(void);
void menu(char key);
UFR_STATUS NewCardInField(uint8_t sak, uint8_t *uid, uint8_t uid_size);
UFR_STATUS ReaderOpeningMode();
c_string GetDlTypeName(uint8_t dl_type_code);
//------------------------------------------------------------------------------
int main(void)
{
    char key;
	bool card_in_field = false;
	uint8_t old_sak = 0, old_uid_size = 0, old_uid[10];
	uint8_t sak, uid_size, uid[10];
	UFR_STATUS status;

	status = ReaderOpeningMode();

    if(!status)
    {
        printf("--------------------------------------------------\n");
        printf("       uFR NFC reader successfully opened.\n");
        printf("--------------------------------------------------\n");
        ReaderUISignal(1, 1);
    }
    else
    {
        cout << "Error while trying to open reader, status is " << UFR_Status2String(status) << endl;
        return EXIT_FAILURE;
    }

    #if __WIN32 || __WIN64
			Sleep(300);
#else // if linux || __linux__ || __APPLE__
			usleep(300000);
#endif

    usage();

	do
	{
		while (!_kbhit())
		{
			#if __WIN32 || __WIN64
			Sleep(300);
			#else // if linux || __linux__ || __APPLE__
				usleep(300000);
			#endif
			status = GetCardIdEx(&sak, uid, &uid_size);
			switch (status)
			{
				case UFR_OK:
					if (card_in_field)
					{
						if (old_sak != sak || old_uid_size != uid_size || memcmp(old_uid, uid, uid_size))
						{
							old_sak = sak;
							old_uid_size = uid_size;
							memcpy(old_uid, uid, uid_size);
							NewCardInField(sak, uid, uid_size);
						}
					}
					else
					{
						old_sak = sak;
						old_uid_size = uid_size;
						memcpy(old_uid, uid, uid_size);
						NewCardInField(sak, uid, uid_size);
						card_in_field = true;
					}
					break;
				case UFR_NO_CARD:
					card_in_field = false;
					status = UFR_OK;
					break;
				default:
					ReaderClose();
					printf(" Fatal error while trying to read card, status is: %s\n", UFR_Status2String(status));
					getchar();
					return EXIT_FAILURE;
			}
		}
		
		key = _getch();
		menu(key);
		
	}
	while (key != '\x1b');

	ReaderClose();

	return EXIT_SUCCESS;
}

UFR_STATUS ReaderOpeningMode()
{
    char mode = 0;
    uint32_t reader_type = 0;
    string portNameStr = "";
    string portInterfaceStr = "";
    string argumentStr = "";
    uint32_t port_interface = 0;
    UFR_STATUS status;

    cout << "Choose reader opening mode:" << endl;
    cout << "1. Simple reader open" << endl;
    cout << "2. Advanced reader open" << endl;
	#if linux || __linux__ || __APPLE__
	mode = getchar();
	#else
    mode = _getch();
	#endif
	
    switch(mode)
    {
        case '1':
            status = ReaderOpen();
            break;

        case '2':
            cout << "Enter reader type: " << endl;
			scanf("%d%*c", &reader_type);
            fflush(stdin);
            cout << endl << "Enter port name: " << endl;
            cin >> portInterfaceStr;
			fflush(stdin);
            cout << endl << "Enter port interface: " << endl;
            cin >> portInterfaceStr;
			fflush(stdin);
            cout << endl << "Enter argument: " << endl;
            cin >> argumentStr;
			fflush(stdin);

            if(portInterfaceStr == "U")
            {
                port_interface = 85;
            }
            else if(portInterfaceStr == "T")
            {
                port_interface = 84;
            }
            else
            {
                port_interface = atoi(portInterfaceStr.c_str());
            }

            status = ReaderOpenEx(reader_type, portNameStr.c_str(), port_interface, (void * )argumentStr.c_str());
            break;

        default:
            cout << "Wrong input choose 1 or 2" << endl;
            break;
    }

    return status;
}

//------------------------------------------------------------------------------
void menu(char key)
{
	switch (key)
	{
		case '1':
		    changeAuthMode();
		    printf("--------------------------------------------------\n");
		    usage();
			break;

		case '2':
		    changeAuthenticationKey();
		    printf("--------------------------------------------------\n");
		    usage();
			break;

		case '3':
		    changeKeyIndex();
		    printf("--------------------------------------------------\n");
		    usage();
			break;

        case '4':
            changeProvidedKey();
            printf("--------------------------------------------------\n");
            usage();
            break;

        case '5':
            operation_BlockRead();
            printf("--------------------------------------------------\n");
            break;

        case '6':
            operation_BlockWrite();
            printf("--------------------------------------------------\n");
            break;

        case '7':
            operation_LinearRead();
            printf("--------------------------------------------------\n");
            break;

        case '8':
            operation_LinearWrite();
            printf("--------------------------------------------------\n");
            break;

        case 'a':
        case 'A':
            operation_ReaderKeyWriteAes();
            printf("--------------------------------------------------\n");
            break;

        case 'c':
        case 'C':
            operation_ReaderKeyWrite();
            printf("--------------------------------------------------\n");
            break;

		case '\x1b':
			break;

		default:
			usage();
			break;
	}
}
//------------------------------------------------------------------------------
UFR_STATUS NewCardInField(uint8_t sak, uint8_t *uid, uint8_t uid_size)
{
	UFR_STATUS status;
	uint8_t dl_card_type;

	status = GetDlogicCardType(&dl_card_type);
	if (status != UFR_OK)
		return status;

	printf("\a-------------------------------------------------------------------\n");
	printf("Card type: %s, sak = 0x%02X, uid[%d] = ", GetDlTypeName(dl_card_type), sak, uid_size);
	cout << ConvertToHexArray(uid, uid_size, ":") << endl;
	printf("-------------------------------------------------------------------\n");

	return UFR_OK;
}

c_string GetDlTypeName(uint8_t dl_type_code) {

	switch (dl_type_code) {
	case DL_MIFARE_ULTRALIGHT:
		return "DL_MIFARE_ULTRALIGHT";
	case DL_MIFARE_ULTRALIGHT_EV1_11:
		return "DL_MIFARE_ULTRALIGHT_EV1_11";
	case DL_MIFARE_ULTRALIGHT_EV1_21:
		return "DL_MIFARE_ULTRALIGHT_EV1_21";
	case DL_MIFARE_ULTRALIGHT_C:
		return "DL_MIFARE_ULTRALIGHT_C";
	case DL_NTAG_203:
		return "DL_NTAG_203";
	case DL_NTAG_210:
		return "DL_NTAG_210";
	case DL_NTAG_212:
		return "DL_NTAG_212";
	case DL_NTAG_213:
		return "DL_NTAG_213";
	case DL_NTAG_215:
		return "DL_NTAG_215";
	case DL_NTAG_216:
		return "DL_NTAG_216";
	case DL_MIKRON_MIK640D:
		return "DL_MIKRON_MIK640D";
	case NFC_T2T_GENERIC:
		return "NFC_T2T_GENERIC";
	case DL_MIFARE_MINI:
		return "DL_MIFARE_MINI";
	case DL_MIFARE_CLASSIC_1K:
		return "DL_MIFARE_CLASSIC_1K";
	case DL_MIFARE_CLASSIC_4K:
		return "DL_MIFARE_CLASSIC_4K";
	case DL_MIFARE_PLUS_S_2K_SL0:
		return "DL_MIFARE_PLUS_S_2K_SL0";
	case DL_MIFARE_PLUS_S_4K_SL0:
		return "DL_MIFARE_PLUS_S_4K_SL0";
	case DL_MIFARE_PLUS_X_2K_SL0:
		return "DL_MIFARE_PLUS_X_2K_SL0";
	case DL_MIFARE_PLUS_X_4K_SL0:
		return "DL_MIFARE_PLUS_X_4K_SL0";
	case DL_MIFARE_DESFIRE:
		return "DL_MIFARE_DESFIRE";
	case DL_MIFARE_DESFIRE_EV1_2K:
		return "DL_MIFARE_DESFIRE_EV1_2K";
	case DL_MIFARE_DESFIRE_EV1_4K:
		return "DL_MIFARE_DESFIRE_EV1_4K";
	case DL_MIFARE_DESFIRE_EV1_8K:
		return "DL_MIFARE_DESFIRE_EV1_8K";
	case DL_MIFARE_DESFIRE_EV2_2K:
		return "DL_MIFARE_DESFIRE_EV2_2K";
	case DL_MIFARE_DESFIRE_EV2_4K:
		return "DL_MIFARE_DESFIRE_EV2_4K";
	case DL_MIFARE_DESFIRE_EV2_8K:
		return "DL_MIFARE_DESFIRE_EV2_8K";
	case DL_MIFARE_PLUS_S_2K_SL1:
		return "DL_MIFARE_PLUS_S_2K_SL1";
	case DL_MIFARE_PLUS_X_2K_SL1:
		return "DL_MIFARE_PLUS_X_2K_SL1";
	case DL_MIFARE_PLUS_EV1_2K_SL1:
		return "DL_MIFARE_PLUS_EV1_2K_SL1";
	case DL_MIFARE_PLUS_X_2K_SL2:
		return "DL_MIFARE_PLUS_X_2K_SL2";
	case DL_MIFARE_PLUS_S_2K_SL3:
		return "DL_MIFARE_PLUS_S_2K_SL3";
	case DL_MIFARE_PLUS_X_2K_SL3:
		return "DL_MIFARE_PLUS_X_2K_SL3";
	case DL_MIFARE_PLUS_EV1_2K_SL3:
		return "DL_MIFARE_PLUS_EV1_2K_SL3";
	case DL_MIFARE_PLUS_S_4K_SL1:
		return "DL_MIFARE_PLUS_S_4K_SL1";
	case DL_MIFARE_PLUS_X_4K_SL1:
		return "DL_MIFARE_PLUS_X_4K_SL1";
	case DL_MIFARE_PLUS_EV1_4K_SL1:
		return "DL_MIFARE_PLUS_EV1_4K_SL1";
	case DL_MIFARE_PLUS_X_4K_SL2:
		return "DL_MIFARE_PLUS_X_4K_SL2";
	case DL_MIFARE_PLUS_S_4K_SL3:
		return "DL_MIFARE_PLUS_S_4K_SL3";
	case DL_MIFARE_PLUS_X_4K_SL3:
		return "DL_MIFARE_PLUS_X_4K_SL3";
	case DL_MIFARE_PLUS_EV1_4K_SL3:
		return "DL_MIFARE_PLUS_EV1_4K_SL3";
	case DL_GENERIC_ISO14443_4:
		return "DL_GENERIC_ISO_14443_4";
	case DL_GENERIC_ISO14443_4_TYPE_B:
		return "DL_GENERIC_ISO14443_4_TYPE_B";
	case DL_GENERIC_ISO14443_3_TYPE_B:
		return "DL_GENERIC_ISO14443_3_TYPE_B";
	case DL_IMEI_UID:
		return "DL_IMEI_UID";
	}
	return "UNKNOWN CARD";
}
