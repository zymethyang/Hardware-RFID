#include <SPI.h>
#include <MFRC522.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WiFi.h>

#define SS_PIN 2 //D4
#define RST_PIN 0 //D3

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

MFRC522::MIFARE_Key key;

/**
 * Initialize.
 */
void setup() {
    Serial.begin(9600); // Initialize serial communications with the PC
    while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
    SPI.begin();        // Init SPI bus
    mfrc522.PCD_Init(); // Init MFRC522 card

    // Prepare the key (used both as key A and as key B)
    // using FFFFFFFFFFFFh which is the default at chip delivery from the factory
    // Khai báo key A và key B
    for (byte i = 0; i < 6; i++) {
        key.keyByte[i] = 0x11;
    }

    Serial.println(F("Mời quét thẻ"));
    Serial.print(F("Using key (for A and B):"));
    dump_byte_array(key.keyByte, MFRC522::MF_KEY_SIZE);
    Serial.println();
    
    WiFi.begin("Temp", "987654321");
    while (WiFi.status() != WL_CONNECTED) {  //Khởi tạo kết nối WIFI
      delay(500);
      Serial.println("Đang chờ kết nối"); 
    }
    pinMode(16, OUTPUT);
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
    //In ra UID thẻ
    Serial.print(F("Card UID:"));
    dump_byte_array(mfrc522.uid.uidByte, mfrc522.uid.size);
    Serial.println();
    //In ra loại thẻ
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
    Serial.println(mfrc522.PICC_GetTypeName(piccType));

    // Check for compatibility
    if (    piccType != MFRC522::PICC_TYPE_MIFARE_MINI
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_1K
        &&  piccType != MFRC522::PICC_TYPE_MIFARE_4K) {
        Serial.println(F("Chỉ sử dụng được với loại thẻ Mifare Classic."));
        return;
    }


    byte sector         = 1; //Chọn sector 1
    byte blockAddr      = 4; //Block chứa mã số sinh viên
    byte trailerBlock   = 7; //Chứa key a key b....
    
    MFRC522::StatusCode status;
    byte buffer[18];
    byte size = sizeof(buffer);

    // Xác nhận sử dụng key A
    Serial.println(F("Đang xác nhận sử dụng key A..."));
    status = (MFRC522::StatusCode) mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, trailerBlock, &key, &(mfrc522.uid));
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("PCD_Authenticate() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
        return;
    }
    
    // Đọc dữ liệu từ Block
    Serial.print(F("Đọc dữ liệu từ block ")); Serial.print(blockAddr);
    Serial.println(F(" ..."));
    
    status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(blockAddr, buffer, &size);
    if (status != MFRC522::STATUS_OK) {
        Serial.print(F("MIFARE_Read() failed: "));
        Serial.println(mfrc522.GetStatusCodeName(status));
    }
    
    String item = String("http://backend-rfid.herokuapp.com/student/add/");
    for(int k=0; k<8; k++){
      item += String(buffer[k]);
    }
    
   Serial.println(item);

   HTTPClient http;    //Khai báo đối tượng của class HTTPClient
 
   http.begin(item);      //Chuẩn bị gửi dữ liệu
   http.addHeader("Content-Type", "text/plain");  //Specify content-type header

   int httpCode = http.GET();
   String payload = http.getString();                  //Get the response payload
 
   Serial.println(httpCode);   //Print HTTP return code
   Serial.println(payload);    //Print request response payload

   if(payload=="true"){
      digitalWrite(16, HIGH);
      delay(3000);
      digitalWrite(16, LOW);
    }
   
   
   // Halt PICC
   mfrc522.PICC_HaltA();
   // Stop encryption on PCD
   mfrc522.PCD_StopCrypto1();
}

void dump_byte_array(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i], HEX);
    }
}
