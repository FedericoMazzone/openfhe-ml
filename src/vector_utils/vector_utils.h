#include <cstdint>
#include <vector>


/**
 * Print vector.
 * @param vector vector to print
 */
void printVector(
    const std::vector<int64_t> &vector
);


/**
 * Print matrix.
 * @param matrix matrix to print
 */
void printMatrix(
    const std::vector<std::vector<int64_t>> &matrix
);


/**
 * Add two vectors elementwise.
 * @param vector1 first input vector
 * @param vector2 second input vector
 * @return the sum of the two input vectors
 */
std::vector<int64_t> addVectors(
    const std::vector<int64_t> &vector1,
    const std::vector<int64_t> &vector2
);


/**
 * Multiply two vectors elementwise.
 * @param vector1 first input vector
 * @param vector2 second input vector
 * @return the product of the two input vectors
 */
std::vector<int64_t> multVectors(
    const std::vector<int64_t> &vector1,
    const std::vector<int64_t> &vector2
);


/**
 * Generate random vector of size length, with values in [-maxValue, maxValue).
 * @param length desired length of the vector
 * @param maxValue absolute maximum value of the coefficients
 * @return random vector
 */
std::vector<int64_t> genRandVect(
    size_t length,
    int64_t maxValue
);


/**
 * Generate random matrix of size (rows x cols), with values in [-maxValue,
 * maxValue).
 * @param rows desired number of rows
 * @param cols desired number of columns
 * @param maxValue absolute maximum value of the coefficients
 * @return random matrix
 */
std::vector<std::vector<int64_t>> genRandMatrix(
    size_t rows,
    size_t cols,
    int64_t maxValue
);


/**
 * Transpose the given matrix.
 * @param matrix input matrix
 * @return transposed matrix
 */
std::vector<std::vector<int64_t>> transpose(
    std::vector<std::vector<int64_t>> matrix
);


/**
 * Compute the least power of two greater or equal than the input value.
 * @param n input value
 * @return least power of two >= n
 */
size_t nextPowerOf2(
    size_t n
);


/**
 * Resize the input matrix to reach the desired number of rows and columns, by
 * padding with 0s if necessary.
 * @param matrix input matrix
 * @param numRows output's number of rows
 * @param numCols output's number of columns
 * @return resized matrix
 */
std::vector<std::vector<int64_t>> resizeMatrix(
    std::vector<std::vector<int64_t>> matrix,
    size_t numRows,
    size_t numCols
);


/**
 * Flatten the input matrix.
 * @param matrix input matrix
 * @param direction true for row-wise, false for column-wise
 * @return flattened matrix
 */
std::vector<int64_t> flattenMatrix(
    std::vector<std::vector<int64_t>> matrix,
    bool direction = true
);


/**
 * Scale up a float vector to int for a given scale.
 * @param vector input vector
 * @param scale scale
 * @return scaled vector (scale * vector)
 */
std::vector<int64_t> scaleVector(
    const std::vector<float> &vector,
    const int scale
);


/**
 * Scale up a float matrix to int for a given scale.
 * @param matrix input matrix
 * @param scale scale
 * @return scaled matrix (scale * matrix)
 */
std::vector<std::vector<int64_t>> scaleMatrix(
    const std::vector<std::vector<float>> &matrix,
    const int scale
);


/**
 * Compute the argmax of a given vector.
 * @param vector input vector
 * @return argmax(vector)
 */
size_t argmax(
    const std::vector<int64_t> &vector
);
