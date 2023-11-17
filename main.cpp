#include <iostream>
#include <fstream>
#include <unistd.h>
#include <arpa/inet.h>
#include <opencv2/opencv.hpp>
#include <openssl/aes.h>
#include <openssl/evp.h>

using namespace std;
using namespace cv;

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

    // Receive the size of the encrypted image from the server
    uint32_t encryptedImageSize;
    recv(clientSocket, &encryptedImageSize, sizeof(encryptedImageSize), 0);

    // Receive the size of the key from the server
    uint32_t keySize;
    recv(clientSocket, &keySize, sizeof(keySize), 0);

    // Receive the encrypted image data from the server
    vector<uint8_t> encryptedImageData(encryptedImageSize);
    recv(clientSocket, encryptedImageData.data(), encryptedImageSize, 0);

    // Receive the key from the server
    vector<uint8_t> aesKey(keySize);
    recv(clientSocket, aesKey.data(), keySize, 0);

    // Decrypt the image with AES
    vector<uint8_t> decryptedImageData;
    decryptAES(encryptedImageData, decryptedImageData, aesKey);

    // Convert the received image data to Mat
    Mat receivedImage = imdecode(decryptedImageData, IMREAD_UNCHANGED);

    // Muestra la imagen
    imshow("Imagen Recibida por el Estudiante", receivedImage);
    waitKey(0);

    // Cierra el socket
    close(clientSocket);

    return 0;
}

