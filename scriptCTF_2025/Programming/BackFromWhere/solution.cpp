#include <bits/stdc++.h>
using namespace std;

int main() {
    int n = 1000;
    vector<vector<vector<vector<int>>>> dp(n, vector<vector<vector<int>>>(n));
    for (int i = 0; i < n; i++) {
        cout << i << endl;
        for (int j = 0; j < n; j++) {
            int x;
            cin >> x;

            int twoes = 0, fives = 0;
            while (x % 2 == 0) {
                twoes++;
                x /= 2;
            }
            while (x % 5 == 0) {
                fives++;
                x /= 5;
            }
            
            vector<vector<int>> nums;
            
            if (i != 0) {
                for (vector<int> p : dp[i - 1][j])
                    nums.push_back({p[0] + twoes, p[1] + fives});
            }

            if (j != 0) {
                for (vector<int> p : dp[i][j - 1])
                    nums.push_back({p[0] + twoes, p[1] + fives});
            }

            if (nums.size() == 0) {
                dp[i][j] = {{twoes, fives}};
                continue;
            }

            int fivemaxindex = 0, twomaxindex = 0;
            for (int i = 1; i < nums.size(); i++) { 
                if (nums[i][1] > nums[fivemaxindex][1] || (nums[i][1] == nums[fivemaxindex][1] && nums[i][0] > nums[fivemaxindex][0]))
                    fivemaxindex = i;
                if (nums[i][0] > nums[twomaxindex][0] || (nums[i][0] == nums[twomaxindex][0] && nums[i][1] > nums[twomaxindex][1]))
                    twomaxindex = i;
            }


            if (fivemaxindex != twomaxindex)
                dp[i][j] = {nums[fivemaxindex], nums[twomaxindex]};
            else
                dp[i][j] = {nums[fivemaxindex]};
        }
    }

    int ans = 0;
    for (vector<int> p : dp.back().back())
        ans = max(ans, min(p[0], p[1]));

    cout << ans << endl;
}
