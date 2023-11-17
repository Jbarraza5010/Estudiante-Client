#include <iostream>
#include <fstream>
#include <unistd.h>
#include <arpa/inet.h>
#include <opencv2/opencv.hpp>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace std;
using namespace cv;

// Carga el key privado RSA
RSA* loadPrivateKey(const char* privateKeyPath) {
    FILE* file = fopen(privateKeyPath, "r");
    if (!file) {
        cerr << "Error loading private key file" << endl;
        exit(EXIT_FAILURE);
    }
    RSA* rsa = PEM_read_RSAPrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return rsa;
}

// Decripta la informacion usando RSA key
vector<uint8_t> decryptRSA(const uint8_t* data, size_t dataSize, RSA* rsaKey) {
    int rsaSize = RSA_size(rsaKey);
    vector<uint8_t> decryptedData(rsaSize);

    int result = RSA_private_decrypt(static_cast<int>(dataSize), data, decryptedData.data(), rsaKey, RSA_PKCS1_PADDING);
    if (result == -1) {
        ERR_print_errors_fp(stderr);
        cerr << "RSA decryption failed" << endl;
        exit(EXIT_FAILURE);
    }

    return decryptedData;
}

void decryptAES(const vector<uint8_t>& input, vector<uint8_t>& output, const vector<uint8_t>& key) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;

    // Crea e inicializa el contexto
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.data(), NULL);

    // Crea el output buffer
    output.resize(input.size());

    // Realiza la decriptacion
    EVP_DecryptUpdate(ctx, output.data(), &len, input.data(), input.size());
    plaintext_len = len;

    // Finaliza la decriptacion
    EVP_DecryptFinal_ex(ctx, output.data() + len, &len);
    plaintext_len += len;

    // Limpieza
    EVP_CIPHER_CTX_free(ctx);
    output.resize(plaintext_len);
}

int main() {
    // Crea el socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        cerr << "Error creando el socket" << endl;
        return -1;
    }

    // Especifica el puerto
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &serverAddress.sin_addr);

    // Conecta al servidor
    if (connect(clientSocket, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) == -1) {
        cerr << "Error conectandose al server" << endl;
        close(clientSocket);
        return -1;
    }

    // Recibe el tamaño de la imagen cifrada desde el servidor
    uint32_t encryptedImageSize;
    recv(clientSocket, &encryptedImageSize, sizeof(encryptedImageSize), 0);

    // Recibe el tamaño de la clave desde el servidor
    uint32_t keySize;
    recv(clientSocket, &keySize, sizeof(keySize), 0);

    // Recibe el identificador del algoritmo desde el servidor
    uint8_t algorithmIdentifier;
    recv(clientSocket, &algorithmIdentifier, sizeof(algorithmIdentifier), 0);

    if (algorithmIdentifier == 1) {
        // Recibe los datos de la imagen cifrada desde el servidor
        vector<uint8_t> encryptedImageData(encryptedImageSize);
        recv(clientSocket, encryptedImageData.data(), encryptedImageSize, 0);

        // Recibe la clave desde el servidor
        vector<uint8_t> aesKey(keySize);
        recv(clientSocket, aesKey.data(), keySize, 0);

        // Desencripta la imagen con AES
        vector<uint8_t> decryptedImageData;
        decryptAES(encryptedImageData, decryptedImageData, aesKey);

        // Convierte los datos de la imagen recibidos a formato Mat
        Mat receivedImage = imdecode(decryptedImageData, IMREAD_UNCHANGED);

        // Muestra la imagen
        imshow("Imagen Recibida por el Estudiante", receivedImage);
        waitKey(0);
    } else if (algorithmIdentifier == 2) {
        // Carga el key privado
        RSA* privateKey = loadPrivateKey("/home/tomeito/CLionProjects/Estudiante-Client/private_key.pem");

        // Recive el tamaño del key usando AES debido al tamaño
        uint32_t encryptedAesKeySize;
        recv(clientSocket, &encryptedAesKeySize, sizeof(encryptedAesKeySize), 0);

        // Recive el key AES
        vector<uint8_t> encryptedAesKey(encryptedAesKeySize);
        recv(clientSocket, encryptedAesKey.data(), encryptedAesKeySize, 0);

        // Decripta el key AES usando RSA
        vector<uint8_t> aesKey = decryptRSA(encryptedAesKey.data(), encryptedAesKeySize, privateKey);

        // Recive el tamaño de la imagen
        uint32_t encryptedImageSize;
        recv(clientSocket, &encryptedImageSize, sizeof(encryptedImageSize), 0);

        // Recive la informacion de la imagen
        vector<uint8_t> encryptedImageData(encryptedImageSize);
        recv(clientSocket, encryptedImageData.data(), encryptedImageSize, 0);

        // Decripta la informacion de la imagen usando AES
        vector<uint8_t> decryptedImageData;
        decryptAES(encryptedImageData, decryptedImageData, aesKey);

        // Convierte los datos de la imagen recibidos a formato Mat
        Mat receivedImage = imdecode(decryptedImageData, IMREAD_UNCHANGED);

        // Checkea si la decriptacion funciono
        if (decryptedImageData.empty()) {
            cerr << "Error decrypting image with AES" << endl;
            return -1;
        }

        if (receivedImage.empty()) {
            cerr << "Error decoding image" << endl;
            return -1;
        }

        // Muestra la imagen
        imshow("Imagen Recibida por el Estudiante", receivedImage);
        waitKey(0);
    }

    // Cierra el socket
    close(clientSocket);

    return 0;
}