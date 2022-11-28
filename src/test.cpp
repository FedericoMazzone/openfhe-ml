#include "data_utils/load_mnist.h"

#include <iostream>
#include <vector>


int main(int argc, char* argv[]) {
    
    std::vector<std::vector<int64_t>> trainX, testX;
    std::vector<int64_t> trainY, testY;

    loadMNIST(trainX, trainY, testX, testY);

    for (size_t i = 0; i < trainX.size(); i++) {
        std::cout << i << " ";
        for (auto value : trainX[i])
            std::cout << value;
        std::cout << trainY[i] << std::endl;
    }

    for (size_t i = 0; i < testX.size(); i++) {
        std::cout << i << " ";
        for (auto value : testX[i])
            std::cout << value;
        std::cout << testY[i] << std::endl;
    }

}
