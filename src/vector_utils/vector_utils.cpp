#include "vector_utils.h"

#include <algorithm>
#include <cmath>
#include <ctime>
#include <iostream>


void printVector(
    const std::vector<int64_t> &vector
)
{
    std::cout << "[ ";
    for (int64_t v : vector)
        std::cout << v << " ";
    std::cout << "]" << std::endl;
}


void printMatrix(
    const std::vector<std::vector<int64_t>> &matrix
)
{
    std::cout << "[" << std::endl;
    for (std::vector<int64_t> vector : matrix) {
        std::cout << "   [ ";
        for (int64_t v : vector)
            std::cout << v << " ";
        std::cout << "]" << std::endl;
    }
    std::cout << "]" << std::endl;
}


std::vector<int64_t> addVectors(
    const std::vector<int64_t> &vector1,
    const std::vector<int64_t> &vector2,
    const int64_t &modulus
)
{
    std::vector<int64_t> result;
    if (modulus == 0)
        for (size_t i = 0; i < vector1.size(); i++)
            result.push_back(vector1[i] + vector2[i]);
    else
        for (size_t i = 0; i < vector1.size(); i++)
            result.push_back(mod(vector1[i] + vector2[i], modulus));
    return result;
}


std::vector<int64_t> multVectors(
    const std::vector<int64_t> &vector1,
    const std::vector<int64_t> &vector2
)
{
    std::vector<int64_t> result;
    for (size_t i = 0; i < vector1.size(); i++)
        result.push_back(vector1[i] * vector2[i]);
    return result;
}


std::vector<int64_t> genRandVect(
    size_t length,
    int64_t maxValue
)
{
    std::srand(unsigned(std::time(nullptr)));
    auto myrand = [maxValue] () {
        return (std::rand() % (maxValue << 1)) - maxValue;
    };
    std::vector<int64_t> vector(length);
    std::generate(vector.begin(), vector.end(), myrand);
    return vector;
}


std::vector<std::vector<int64_t>> genRandMatrix(
    size_t rows,
    size_t cols,
    int64_t maxValue
)
{
    std::srand(unsigned(std::time(nullptr)));
    auto myrand = [maxValue] () {
        return (std::rand() % (maxValue << 1)) - maxValue;
    };
    std::vector<std::vector<int64_t>> matrix(rows, std::vector<int64_t>(cols));
    for (size_t i = 0; i < rows; i++)
        std::generate(matrix[i].begin(), matrix[i].end(), myrand);
    return matrix;
}


std::vector<std::vector<int64_t>> transpose(
    std::vector<std::vector<int64_t>> matrix
)
{
    std::vector<std::vector<int64_t>> matrixT(
        matrix[0].size(),
        std::vector<int64_t>(matrix.size())
    );
    for (size_t i = 0; i < matrix[0].size(); i++) 
        for (size_t j = 0; j < matrix.size(); j++)
            matrixT[i][j] = matrix[j][i];
    return matrixT;
}


size_t nextPowerOf2(
    size_t n
)
{
    if (n == 0 || n == 1) return 1;
    else return 1 << ((int) std::log2(n - 1) + 1);
}


std::vector<std::vector<int64_t>> resizeMatrix(
    std::vector<std::vector<int64_t>> matrix,
    size_t numRows,
    size_t numCols
)
{
    for (auto &row : matrix) row.resize(numCols, 0);
    matrix.resize(numRows, std::vector<int64_t>(numCols, 0));
    return matrix;
}


std::vector<int64_t> flattenMatrix(
    std::vector<std::vector<int64_t>> matrix,
    bool direction
)
{
    std::vector<int64_t> res;
    if (direction)
        for (auto &row : matrix)
            res.insert(end(res), begin(row), end(row));
    else {
        for (size_t i = 0; i < matrix[0].size(); i++) 
            for (size_t j = 0; j < matrix.size(); j++)
                res.push_back(matrix[j][i]);
    }
    return res;
}


std::vector<int64_t> scaleVector(
    const std::vector<float> &vector,
    const int scale
)
{
    std::vector<int64_t> result;
    for (float v : vector)
        result.push_back(v * scale);
    return result;
}


std::vector<std::vector<int64_t>> scaleMatrix(
    const std::vector<std::vector<float>> &matrix,
    const int scale
)
{
    std::vector<std::vector<int64_t>> result;
    std::vector<int64_t> row;
    for (std::vector<float> vector : matrix) {
        for (float v : vector)
            row.push_back(v * scale);
        result.push_back(row);
        row.clear();
    }
    return result;
}


size_t argmax(
    const std::vector<int64_t> &vector
)
{
    size_t argmax = 0;
    int64_t max = vector[argmax];
    for (size_t i = 0; i < vector.size(); i++) {
        if (vector[i] > max) {
            argmax = i;
            max = vector[i];
        }
    }
    return argmax;
}


int64_t mod(
    int64_t value,
    const int64_t &modulus
)
{
    value = value % modulus;

    if (value > ((modulus % 2 == 0) ? (modulus >> 1) - 1 : (modulus >> 1)))
        value -= modulus;
    else if (value < - (modulus >> 1))
        value += modulus;

    return value;
}
