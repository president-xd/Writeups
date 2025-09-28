#include<bits/stdc++.h>
using namespace std;

int main() {
    int n = 123456;
    vector<long long> a(n), pref(n + 1);
    cin >> a[0];
    for (int i = 1; i < n; i++) 
        cin >> a[i], pref[i] = pref[i - 1] + a[i];

    for (int i = 0; i < n; i++) {
        int l, r;
        cin >> l >> r;
        if (l)
            cout << pref[r] - pref[l - 1] << endl;
        else
            cout << pref[r] << endl;
    }
}

