#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <openssl/sha.h>
#include <ctype.h>
#include <string.h>



uint8_t hex_to_byte(unsigned char h1, unsigned char h2) {

   uint8_t x = 0;

   uint8_t y = 0;



   //Convert h1 to a decimal value

   if (h1 >= '0' && h1 <= '9') {

       x += h1 - '0';

   }

   else if (h1 >= 'a' && h1 <= 'f'){

       x += h1 - 'a' + 10;

   }



  //Convert h2 to a decimal value

   if (h2 >= '0' && h2 <= '9') {

       y += h2 - '0';

   }

   else if (h2 >= 'a' && h2 <= 'f'){

       y += h2 - 'a' + 10;

   }

   //TODO: Determine what the function should return

       return (16*x) + y;

}



//TESTING

void test_hex_to_byte() {

       assert(hex_to_byte('c', '8') == 200);

       assert(hex_to_byte('0', '3') == 3);

       assert(hex_to_byte('0', 'a') == 10);

       assert(hex_to_byte('1', '0') == 16);

       printf("hex_to_byte tests passed!\n");

}



void hexstr_to_hash(char hexstr[], unsigned char hash[32]) {

       int i;

       for (i = 0; i < 32; i++) {

               hash[i] = hex_to_byte(hexstr[2 * i], hexstr[2 * i + 1]);

       }

}



//TESTING

void test_hexstr_to_hash() {

       char hexstr[64] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";

       unsigned char hash[32];

       hexstr_to_hash(hexstr, hash);



       assert(hash[0] == 0xa2);

       assert(hash[31] == 0xfd);

       printf("hexstr_to_hash tests passed!\n");

}



int8_t check_password(char password[], unsigned char given_hash[32]){

       unsigned char computed_hash[32];

  //Computer the SHA-256 hash of the provided password

       SHA256_CTX sha256;

       SHA256_Init(&sha256);

       SHA256_Update(&sha256, password, strlen(password));

       SHA256_Final(computed_hash, &sha256);



       int i;

       for (i = 0; i < 32; i++){

               if(computed_hash[i] != given_hash[i]){

                       return 0; //if the hashes don't match

               }

       }



       return 1; //if the hashes match



}



void test_check_password(){

       char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; // Hash of "password"
  unsigned char given_hash[32];

       hexstr_to_hash(hash_as_hexstr, given_hash);



       //Test matchin password

       assert(check_password("password'", given_hash) == 1);

       //Test non-matching password

       assert(check_password("wrongpass", given_hash) == 0);



       printf("check_password tests passed!\n");

}



int8_t crack_password(char password[], unsigned char given_hash[32]){

       //Check if the original password matches

       if (check_password(password, given_hash)){

               return 1;

       }



       //Uppercase or Lowercase each character and check the hash

       int i;

       for (i = 0; password[i] != '\0'; i++) {
  char original_char = password[i];



               //Uppercase this character

               if (islower(original_char)) {

                       password[i] = toupper(original_char);

                       if (check_password(password, given_hash)) {

                               return 1;

                       }

               }



               //Lowercase this character

               if (isupper(original_char)) {

                       password[i] = tolower(original_char);

                       if (check_password(password, given_hash)) {

                               return 1;

                       }

               }

               //restore OG password before looping to next

               password[i] = original_char;

       }
 return 0; //if no match was found

}



void test_crack_password() {

       char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

       unsigned char given_hash[32];

       hexstr_to_hash(hash_as_hexstr, given_hash);



       //Test exact match

       char password1[] = "password";

       assert(crack_password(password1, given_hash) == 1);

       assert(strcmp(password1, "password") ==0); //password should remain unchanged



       //Test with variation that should match

       char password2[] = "paSsword";

       assert(crack_password(password2, given_hash) == 1);

       assert(strcmp(password2, "password") == 0); //the first 'S' should have been lowercase



       //Test with a variation that should NOT match

     char password3[] = "wrongpass";

       assert(crack_password(password3, given_hash) == 0);



       printf("crack_password tests passed!\n");

}





int main(int argc, char **argv) {

       //UNIT TESTING SECTION

       const int testing = 0; //set this variable to 1 to run unit tests instead of the entire program

       

       if (testing) {

               test_hex_to_byte();

               test_hexstr_to_hash();

               test_check_password();

               test_crack_password();

           // ADD MORE TESTS HERE. MAKE SURE TO ADD TESTS THAT FAIL AS WELL TO SEE WHAT HAPPENS



           printf("ALL TESTS PASSED!\n");

           return 0;

}



       //MAIN PROGRAM SECTION

       if (argc < 2) {

           printf("Error: not enough arguments provided!\n");

           printf("Usage: %s <SHA-256 hash in hex>\n", argv[0]);

           return 1;

       }



       //Convert the given hash in to a 32-byte array

       unsigned char given_hash[32];

       hexstr_to_hash(argv[1], given_hash);



       char password[256]; //holds the input password

       int found = 0;



       //Read passwords from stdin

       while (fgets(password, sizeof(password), stdin)) {

               //remove newline if there'

               password[strcspn(password, "\n")] = 0;

//check id the password or any variation matches the given hash

               if (crack_password(password, given_hash)) {

                       printf("Found password: SHA256(%s) = %s\n", password, argv[1]);

                       found = 1;

                       break;

               }

       }



       if (!found) {



               printf("Did not find a matching password\n");

       }



       return 0;

}




