#include "load_mnist.h"

#include <iostream>
#include <fstream>
#include <string>


/**
 * Load MNIST dataset from data/mnist.txt.
 * @param trainX vector to store the features of training data
 * @param trainY vector to store the labels of training data
 * @param testX vector to store the features of test data
 * @param testY vector to store the labels of test data
 */
void loadMNIST(
        std::vector<std::vector<int64_t>> &trainX,
        std::vector<int64_t> &trainY,
        std::vector<std::vector<int64_t>> &testX,
        std::vector<int64_t> &testY
    )
{
    std::string line;
    std::ifstream inputStream;
    std::vector<int64_t> sample;
    size_t id, i;

    inputStream.open("../data/mnist.txt");

    id = 0;
    while (std::getline(inputStream, line)) {
        for (i = 0; i < line.length() - 1; i++)
            sample.push_back(line[i] - '0');
        if (id < 60000) {
            trainX.push_back(sample);
            trainY.push_back(line[i] - '0');
        } else {
            testX.push_back(sample);
            testY.push_back(line[i] - '0');
        }
        sample.clear();
        id++;
    }

    inputStream.close();
}


// int main(int argc, char* argv[]) {
    
//     std::vector<std::vector<int64_t>> trainX, testX;
//     std::vector<int64_t> trainY, testY;

//     loadMNIST(trainX, trainY, testX, testY);

//     for (size_t i = 0; i < trainX.size(); i++) {
//         std::cout << i << " ";
//         for (auto value : trainX[i])
//             std::cout << value;
//         std::cout << trainY[i] << std::endl;
//     }

//     for (size_t i = 0; i < testX.size(); i++) {
//         std::cout << i << " ";
//         for (auto value : testX[i])
//             std::cout << value;
//         std::cout << testY[i] << std::endl;
//     }

// }
