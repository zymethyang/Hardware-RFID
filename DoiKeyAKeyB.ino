#include <SPI.h>
#include <MFRC522.h>

#define SS_PIN 2 //D4
#define RST_PIN 0 //D3

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

MFRC522::MIFARE_Key key;

void setup() {
    Serial.begin(9600);	// Giao tiếp với máy tính
    while (!Serial);    // Không làm gì cả nếu không có port nào mở
    SPI.begin();		// Setup SPI
    mfrc522.PCD_Init();	// Setup RC522

    // Chuẩn bị sẵn key để xác thực. Nếu thẻ mới mua thì sửa phần này thành key mặc định
    // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0xFF;
    }

    Serial.println(F("Quét thẻ."));
    Serial.print(F("Using key (for A and B):"));
    dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
    
    Serial.println(F("BEWARE: Dữ liệu sẽ được ghi vào sector #1"));
}

/**
 * Main loop.
 */
void loop() {
    // Look for new cards
    if ( ! mfrc522.PICC_IsNewCardPresent())
        return;

    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
        return;

    // Show some details of the PICC (that is: the tag/card)
    Serial.print(F("Card UID:"));
    dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    Serial.println();
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    Serial.println(mfrc522.PICC_GetTypeName(piccType));

    // Check for compatibility
    if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        Serial.println(F("This sample only works with MIFARE Classic cards."));
        return;
    }

    // Khai báo sector và trailerBlock, nơi sẽ được ghi vào key xác thực
    byte sector         = 1;
    byte trailerBlock   = 7;
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);
    int32_t value;

    // Xác thực với key A
    Serial.println(F("Đang xác thực với key A..."));
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

    // Shoư sector 1
    Serial.println(F("Dữ liệu sector 1 là:"));
    mfrc522.PICC_DumpMifareClassicSectorToSerial(&(mfrc522.uid), &key, sector);
    Serial.println();
    
    //      Bytes 0-5:   Key A
    //      Bytes 6-8:   Access Bits
    //      Bytes 9:     User data
    //      Bytes 10-15: Key B (or user data)
    //      Khai báo key a và key b mới để chuẩn bị ghi vào
    byte trailerBuffer[] = {
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11,       // Key A
        0, 0, 0,
        0,
        0x11, 0x11, 0x11,0x11 , 0x11, 0x11};      // Key B
    mfrc522.MIFARE_SetAccessBits(&trailerBuffer[6], 0, 6, 6, 3);

    // Read the sector trailer as it is currently stored on the PICC
    Serial.println(F("Reading sector trailer..."));
    status = mfrc522.MIFARE_Read(trailerBlock, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
    // Check if it matches the desired access pattern already;

    // Authenticate using key B
    Serial.println(F("Authenticating again using key B..."));
    status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }

     // Ghi dữ liệu vào sector
    Serial.println(F("Writing new sector trailer..."));
    status = mfrc522.MIFARE_Write(trailerBlock, trailerBuffer, 16);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Write() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
      return;
    }

    // Halt PICC
    mfrc522.PICC_HaltA();
    // Stop encryption on PCD
    mfrc522.PCD_StopCrypto1();
}

/**
 * Helper routine to dump a byte array as hex values to Serial.
 */
void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}
