#include <iostream>
using namespace std;

int main() {
    long long a[9];
    long long x;

    for (int i = 0; i < 9; i++)
        cin >> a[i];

    cin >> x;

    long long result = 0;

    for (int i = 8; i>= 0; i--) {
        result = result * x + a[i];
    }

    cout << result;
    return 0;
}
