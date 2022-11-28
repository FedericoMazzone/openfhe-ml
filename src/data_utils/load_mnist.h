#include <cstdint>
#include <vector>


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
    );
