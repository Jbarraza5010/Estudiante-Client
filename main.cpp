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

void decryptRSA(const vector<uint8_t>& input, vector<uint8_t>& output, const vector<uint8_t>& privateKey) {
    RSA *rsa = NULL;
    BIO *keyBio = BIO_new_mem_buf(privateKey.data(), privateKey.size());

    if (keyBio == NULL) {
        cerr << "Error creando el objeto BIO" << endl;
        return;
    }

    rsa = PEM_read_bio_RSAPrivateKey(keyBio, NULL, NULL, NULL);
    BIO_free(keyBio);

    if (rsa == NULL) {
        cerr << "Error leyendo la clave privada RSA" << endl;
        return;
    }

    int inputSize = input.size();
    int outputSize = RSA_size(rsa);
    output.resize(outputSize);

    int result = RSA_private_decrypt(inputSize, input.data(), output.data(), rsa, RSA_PKCS1_PADDING);

    if (result == -1) {
        cerr << "Error desencriptando con RSA" << endl;
        RSA_free(rsa);
        return;
    }

    RSA_free(rsa);
}

void decryptAES(const vector<uint8_t>& input, vector<uint8_t>& output, const vector<uint8_t>& key) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key.data(), NULL);

    // Set up the output buffer
    output.resize(input.size());

    // Perform the decryption
    EVP_DecryptUpdate(ctx, output.data(), &len, input.data(), input.size());
    plaintext_len = len;

    // Finalize the decryption
    EVP_DecryptFinal_ex(ctx, output.data() + len, &len);
    plaintext_len += len;

    // Clean up
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
        // Recibe los datos de la imagen cifrada desde el servidor
        vector<uint8_t> encryptedImageData(encryptedImageSize);
        recv(clientSocket, encryptedImageData.data(), encryptedImageSize, 0);

        // Recibe el tamaño de la clave pública RSA desde el servidor
        uint32_t publicKeySize;
        recv(clientSocket, &publicKeySize, sizeof(publicKeySize), 0);
        cout << "Tamaño de la clave pública RSA recibida: " << publicKeySize << endl;

        // Recibe la clave pública RSA desde el servidor
        vector<uint8_t> rsaPublicKey(keySize);
        recv(clientSocket, rsaPublicKey.data(), keySize, 0);

        // Desencripta la imagen con RSA
        vector<uint8_t> decryptedImageData;
        decryptRSA(encryptedImageData, decryptedImageData, rsaPublicKey);

        // Convierte los datos de la imagen recibidos a formato Mat
        Mat receivedImage = imdecode(decryptedImageData, IMREAD_UNCHANGED);

        // Muestra la imagen
        imshow("Imagen Recibida por el Estudiante", receivedImage);
        waitKey(0);
    }

    // Cierra el socket
    close(clientSocket);

    return 0;
}