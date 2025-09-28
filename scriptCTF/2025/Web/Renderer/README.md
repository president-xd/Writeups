# Renderer

# Write-up

By visiting `/render/<filename>`, You can read any files INSIDE the `/static/uploads` directory. Steps to solve:
1. Visit `/developer` and set the cookie to a random value (this ensures that `secret_cookie.txt` is not empty). 

2. Visit `/render/secrets/secret_cookie.txt` to get the cookie

3. Visit `/developer` with the correct cookie to get the flag!

# Flag - scriptCTF{my_c00k135_4r3_n0t_s4f3!}