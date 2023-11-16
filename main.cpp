#include <iostream>
#include <fstream>
#include <unistd.h>
#include <arpa/inet.h>
#include <opencv2/opencv.hpp>

using namespace std;
using namespace cv;

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

    // Input de la imagen a enviar
    Mat image = imread("/home/tomeito/CLionProjects/Client/logo_tec.jpg", IMREAD_UNCHANGED);

    // Convierte la imagen a un set de bytes
    vector<uint8_t> imageData;
    imencode(".jpg", image, imageData);

    // Envia el tamaño de la imagen
    uint32_t imageSize = imageData.size();
    send(clientSocket, &imageSize, sizeof(imageSize), 0);

    // Envia la informacion de la imagen
    send(clientSocket, imageData.data(), imageSize, 0);


    // Recibe el tamaño de la imagen del server
    uint32_t receivedImageSize;
    recv(clientSocket, &receivedImageSize, sizeof(receivedImageSize), 0);

    // Recibe la informacion del server
    vector<uint8_t> receivedImageData(receivedImageSize);
    recv(clientSocket, receivedImageData.data(), receivedImageSize, 0);

    // Convierte la imagen
    Mat receivedImage = imdecode(receivedImageData, IMREAD_UNCHANGED);

    // Muestra la imagen
    imshow("Imagen Recibida por el Estudiante", receivedImage);
    waitKey(0);

    // Cierra el socket
    close(clientSocket);

    return 0;
}

