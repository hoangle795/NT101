#include <iostream>
#include <string>
using namespace std;

string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // chuẩn cổ điển, bỏ J

// tạo ma trận khóa
void createKeyMatrix(string key, char matrix[5][5]) {
    string table = "";
    bool used[26] = {false};
    for (char &c : key) {
        if (c == 'J') c = 'I'; 
        c = toupper(c);
    }

    for (char c : key) {
        if (!used[c - 'A']) {
            table += c;
            used[c - 'A'] = true;
        }
    }

    for (char c : alphabet) {
        if (!used[c - 'A']) {
            table += c;
            used[c - 'A'] = true;
        }
    }

    int k = 0;
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            matrix[i][j] = table[k++];
        }
    }
}

// tìm vị trí ký tự trong ma trận
void findPos(char matrix[5][5], char c, int &x, int &y) {
    if (c == 'J') c = 'I'; // J -> I
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            if (matrix[i][j] == c) {
                x = i; y = j;
                return;
            }
        }
    }
}

// xử lý văn bản trước khi mã hóa
string prepareText(string text) {
    string result = "";
    for (char &c : text) {
        if (c == 'J') c = 'I';
        c = toupper(c);
    }
    for (size_t i = 0; i < text.size(); i++) {
        result += text[i];
        if (i + 1 < text.size() && text[i] == text[i + 1]) {
            result += (text[i] == 'X' ? 'Y' : 'X');
        }
    }
    if (result.size() % 2 == 1) {
        result += (result.back() == 'X' ? 'Y' : 'X');
    }
    return result;
}

// mã hóa
string encrypt(string text, char matrix[5][5]) {
    string prepared = prepareText(text);
    string ans = "";
    for (size_t i = 0; i < prepared.size(); i += 2) {
        int x1, y1, x2, y2;
        findPos(matrix, prepared[i], x1, y1);
        findPos(matrix, prepared[i + 1], x2, y2);

        if (x1 == x2) {
            ans += matrix[x1][(y1 + 1) % 5];
            ans += matrix[x2][(y2 + 1) % 5];
        } else if (y1 == y2) {
            ans += matrix[(x1 + 1) % 5][y1];
            ans += matrix[(x2 + 1) % 5][y2];
        } else {
            ans += matrix[x1][y2];
            ans += matrix[x2][y1];
        }
        ans += " ";
    }
    return ans;
}

// giải mã
string decrypt(string text, char matrix[5][5]) {
    string cleaned = "";
    for (char c : text) if (c != ' ') cleaned += c;

    string ans = "";
    for (size_t i = 0; i < cleaned.size(); i += 2) {
        int x1, y1, x2, y2;
        findPos(matrix, cleaned[i], x1, y1);
        findPos(matrix, cleaned[i + 1], x2, y2);

        if (x1 == x2) {
            ans += matrix[x1][(y1 - 1 + 5) % 5];
            ans += matrix[x2][(y2 - 1 + 5) % 5];
        } else if (y1 == y2) {
            ans += matrix[(x1 - 1 + 5) % 5][y1];
            ans += matrix[(x2 - 1 + 5) % 5][y2];
        } else {
            ans += matrix[x1][y2];
            ans += matrix[x2][y1];
        }
    }
    return ans;
}

// in ma trận
void printMatrix(char matrix[5][5]) {
    cout << "\nKey matrix:\n";
    for (int i = 0; i < 5; i++) {
        for (int j = 0; j < 5; j++) {
            cout << matrix[i][j] << " ";
        }
        cout << endl;
    }
}

int main() {
    string key, text;
    int act;
    char matrix[5][5];

    cout << "Enter key: ";
    cin >> key;
    createKeyMatrix(key, matrix);
    printMatrix(matrix);

    cout << "\nChoose action (1 = Encryption, 2 = Decryption): ";
    cin >> act;
    cout << "Enter text (no spaces): ";
    cin >> text;

    if (act == 1) {
        cout << "\nResult: " << encrypt(text, matrix) << endl;
    } else {
        cout << "\nResult: " << decrypt(text, matrix) << endl;
    }
    return 0;
}
