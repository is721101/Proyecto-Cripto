#include <cstdlib>

#include <iomanip>
#include <sodium.h>
#include <string>
#include <iostream>
#include <sstream> 
#include <fstream> 
#include <stdio.h>
#include <string.h>

#define CHUNK_SIZE 4096
using namespace std;
//Función para encriptar
static int
encrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_t);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
            NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}
//Función para desencriptar
static int
decrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret;
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
            buf_in, rlen, NULL, 0) != 0) {
            goto ret;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            goto ret; 
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}
//Funcion para firmar
static int sign(const char* target_file, unsigned char* pk,  unsigned char* sk, unsigned char* sig) {

    crypto_sign_keypair(pk, sk);

    unsigned char msg[CHUNK_SIZE];


    FILE* file;

    file = fopen(target_file, "rb");
    fread(msg, 1, sizeof msg, file);

    crypto_sign_detached(sig, NULL, msg, sizeof msg, sk);
    int ret = 0;
    fclose(file);

    return ret;
}
//Función para comprobar la firma
static int verify_sign(const char* target_file, unsigned char* pk, unsigned char* sig) {
    unsigned char msg[CHUNK_SIZE];
    int ret = 0;

    FILE* file;

    file = fopen(target_file, "rb");
    fread(msg, 1, sizeof msg, file);

    if (crypto_sign_verify_detached(sig, msg, sizeof msg, pk) != 0) {
        
        std::cout << "no es la firma o archivo correcta" << std::endl;
    }
    else {
        std::cout << "firma correcta" << std::endl;
    }
    fclose(file);

    return ret;
}
//Funcion para generar claves
static int claveSecreta(const char* target_file) {
    unsigned char keyfile[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_keygen(keyfile);
    ofstream archivo(target_file);
    archivo << keyfile;
    archivo.close();
    return 0;

}



int main(void)
{    //Comprobar que esta instalado libsodium
    if (sodium_init() != 0) {
        return 1;
    }
    unsigned char sig[crypto_sign_BYTES];    
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];

    string linea;
    string texto;
    ifstream archivo;
    int op;
    char  path1[CHUNK_SIZE], path2[CHUNK_SIZE], path3[CHUNK_SIZE];


    //Menu iterativo
    do {
        std::cout << "Inserta una opcion" << std::endl;
        std::cout << "1. Generar claves" << std::endl;
        std::cout << "2. Encriptar archivo" << std::endl;
        std::cout << "3. Desencriptar archivo" << std::endl;
        std::cout << "4. Firmar archivo" << std::endl;
        std::cout << "5. Comprobar la firma del archivo" << std::endl;
        std::cout << "6. salir" << std::endl;
        std::cin >> op;
        switch (op) {
         
        case 1: {
            //Generamos la clave secreta
            std::cout << "dirección donde guardar la clave secreta: " << std::endl;
            std::cin >> path1;
            claveSecreta(path1);
            std::cout << "Clave Generada " << std::endl;
            break;
        }
        case 2: {
            std::cout << "dirección del archivo encriptado: " << std::endl;
            std::cin >> path1;

            std::cout << "dirección del archivo a cifrar: " << std::endl;
            std::cin >> path2;
            std::cout << "dirección de la clave secreta: " << std::endl;
            std::cin >> path3;

            archivo.open(path3);
            if (archivo.fail()) {
                cout << "Error al abrir este archivo" << endl;
                return -1;
            }
            //Guardamos el texto en un string
            while (getline(archivo, linea)) {
                texto = texto + linea;
            }

            archivo.close();

            //creamos la llave
            const unsigned char* key = reinterpret_cast<const unsigned char*> (texto.c_str());
             //Llamamos a encrypt
            if (encrypt(path1, path2, key) != 0) {
                return 1;
            }
            std::cout << "Archivo encriptado " << std::endl;
            break;
        }
        case 3: {
            std::cout << "dirección del archivo encriptado: " << std::endl;
            std::cin >> path1;
            std::cout << "dirección del archivo destino: " << std::endl;
            std::cin >> path2;
            std::cout << "dirección de la clave secreta: " << std::endl;
            std::cin >> path3;
            archivo.open(path3);
            if (archivo.fail()) {
                cout << "Error al abrir este archivo" << endl;
                return -1;
            }
            //Guardamos el texto en un string
            while (getline(archivo, linea)) {
                texto = texto + linea;
            }
            archivo.close();
            //creamos la clave
            const unsigned char* key = reinterpret_cast<const unsigned char*> (texto.c_str());
            //Llamamos a decrypt
            if (decrypt(path2, path1, key) != 0) {
                return 1;
            }
            std::cout << "Archivo desencriptado" << std::endl;
            break;
        }
        case 4: {
            //Firmar el documento
            std::cout << "dirección del archivo a firmar: " << std::endl;
            std::cin >> path1;
            if (sign(path1, &*pk ,&*sk, &*sig) != 0) {
                return 1;
            }
            std::cout << "Archivo firmado " << std::endl;
            break;
        }
        case 5: {
            //Comprobar firma
            std::cout << "dirección del archivo  a comprobar: " << std::endl;
            std::cin >> path1;
            if (verify_sign(path1, &*pk, &*sig) != 0) {
                return 1;
            }

            break;
        }

        }
    }while (op != 6);
    return 0;
}