#include<bits/stdc++.h>
using namespace std;

int n = 200000;

vector<int> spf(n + 1); // smallest prime factor

void fill_spf() {
    iota(spf.begin(), spf.end(), 0);
    for (int i = 2; i * i <= n; i++) {
        if (spf[i] == i) {
            for (int j = i * i; j <= n; j += i)
                if (spf[j] == j)
                    spf[j] = i;
        }
    }
}

vector<int> prime_factors(int x) {
    vector<int> factors;
    while (x > 1) {
        int factor = spf[x];
        factors.push_back(factor);
        while (x % factor == 0)
            x /= factor;
    }

    return factors;
}

int main() {
    fill_spf();

    vector<int> best(n + 1); // best[i] = best sequence currently with common factor of i
    int ans = 0;

    for (int i = 0; i < n; i++) {
        int x;
        cin >> x;
        vector<int> factors = prime_factors(x);
        int curbest = 0;
        for (int factor : factors)
            best[factor]++, curbest = max(best[factor], curbest);

        ans = max(ans, curbest);
    }

    cout << ans << endl;
}
