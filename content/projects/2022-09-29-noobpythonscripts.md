+++
title = "Noob Python Scripts"
description = "I used to be proud of this shi*.. -_-"
weight = 0
date = "2022-09-29"

[extra]
#local_image = "/assets/Flag.png"
#link_to = "https://github.com/TheMj0ln1r/NetScan"
+++


# NetScan

This is a basic computer networking based project the script i developed using python which can perform following tasks.

1. Get any websites IP
2. Discover live hosts
3. Discover Hosts and MAC

I used ping to send the ICMP packets to every device connected to network, the response from that device has been analyzed and printed the devices which are responded for the ICMP request.
This process could be slow if the number of hosts to be scanned are increased, but it will works fine as it uses just a basic ping which is available in any operating system.

A TCP scan is also used to get the active hosts in a network this will overcome the ping scan drawbacks, i.e the ICMP packets can be blocked by a firewall in this process we may get the host status as unreachable. To overcome this are going to sent tcp packets to the port 135 using socket module in python.

An arp scan is used to the MAC adrresses of all the hosts connected in a network.

I devoloped this script with less additional modules which can make the scan slow , but this can be executed in any system without any additional requirements.

### Requirements

You may require some python modules

1. subprocess
2. socket
3. platform

These modules will be pre installed on every system, if not then install them with `pip3 or pip`


```bash
git clone https://github.com/TheMj0ln1r/NetScan.git
cd NetScan
python3 NetScan.py
```


### Preview 
![Preview](/assets/img/project_img/netscan/netscan.png)

> If anything should be modified in the script please let me know.

***

# Port Scanner

This is a basic computer networking based project. The script is developed using python which can perform following tasks.
1. Scanning open ports on a single target
2. Scanning open ports in every system in a network
Let's start with the main function.

```python 
def main():

	print("""
	1 > Scan one device
	2 > Scan Entire network
		""")
	choice = int(input("Enter your choice(1/2) : "))

	if choice == 1:

		print("Scanning only one target.. \n")
		global target_ip
		target_ip = input("Enter Target IP or URL : ")

		start_port = int(input("Enter start port : "))
		end_port = int(input("Enter end port : "))
		
		input_check(start_port,end_port)
		single_host_scan(start_port,end_port)
		sys.exit()
	elif choice == 2:

		print("Scanning Entire Network..\n")
		target_ip = input("Enter your IP address : ")
		start_host = int(input("Enter start host : "))
		end_host = int(input("Enter end host : "))
		start_port = int(input("Enter start port : "))
		end_port = int(input("Enter end port : "))
		
		input_check(start_port,end_port)
		host_check(start_host,end_host)
		multi_host_scan(start_host,end_host,start_port,end_port)
		sys.exit()
	else :
		print("Invalid choice.")
		sys.exit()
main()
```
In the beginning, this tool will asks the users for their choice to perform a specific task.
i.e, to scan a single target or an entire network. If the user choose 1, then the tool will take start port and end port as an input from the user. Then the program is going to validate the inputs given, this is done by the `input_check` function. Next the `single_host_scan` will be called. Take look at these two functions.

`input_check()`
	
```python
def input_check(start_port,end_port):
	global target_ip
	ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',target_ip)
	if not ip:
		try :
			target_ip = socket.gethostbyname(target_ip)
		except socket.gaierror :
			print("Unable resolve host address")
			sys.exit()
	if ((start_port < 1) or (end_port > 65535)):
		print("Port numbers are invalid.. \n")
		sys.exit()
```
 In the try block of the input_check function, if a user gave a website as target that url will be changed to IP address here.

`single_host_scan()`

```python
def single_host_scan(start_port,end_port):

	if islive():
		for port in range(start_port,end_port+1):
			thread = threading.Thread(target = single_port,args = (port,))
			thread.start()
			thread.join()
	else:
		print("\t Not reachable.\n")
```
In the above function the islive function will checks that the given host is live or not. If it is live then it is going to scan every port in a given range of that target host.

`islive()`

```python
def islive():
	try:
		if "Linux" in system():
			p = subprocess.run(["ping","-c","1",target_ip],capture_output=True,text=True)
			if p.returncode == 0:
				return True

		if "Windows" in system():
			p = subprocess.run(["ping","-n","1",target_ip],capture_output=True,text=True)
			if p.returncode == 0:
				return True

	except subprocess.CalledProcessError:
		return False
```
islive() function uses a ping scan to check the target is live or not.

If the target is live, a thread is created for each port to increase the speed of the scan. In every thread single_port() function is being called.

`single_port`

```python
def single_port(port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		socket.setdefaulttimeout(1)
		status = s.connect_ex((target_ip,port))
		if(not status):
			print("\tOpen port ",port)
			s.close()
		s.close()
```
By using socket programming the connection request for a port will be sent to the remote host. If the connection was established with a port the status of the port will be printed as open.


Now if the user choose to scan entire network, the same concept is used to check the open ports.The functions involved in entire network scan are `host_check` and `multi_host_scan`.

`host_check()`

```python
def host_check(start_host,end_host):
	if (start_host < 1 or end_host > 255):
		print("Host range in not valid..\n")
		sys.exit()
```

`multi_host_scan()`

```python
def multi_host_scan(start_host,end_host,start_port,end_port):
	global target_ip
	tmp = target_ip
	ip = tmp.split(".")
	ip = ".".join(ip[0:3])+"."
	for host in range(start_host,end_host+1):
		target_ip = ip + str(host)
		print("Scannig Host : "+target_ip+"\n")
		single_host_scan(start_port,end_port)
	sys.exit()
```

I devoloped this script with less additional modules this can be executed in any system without any additional requirements.This scanning process will take less time. 

### Requirements

You may require some python modules

1. subprocess
2. socket
3. platform
4. threading
5. sys

These modules will be pre installed on every system, if not then install them with `pip3 or pip`
### Installation

```text 
git clone https://github.com/TheMj0ln1r/Port_Scanner.git
cd Port_Scanner
python3 Port_Scanner.py
```

### Preview 
![Preview](/assets/img/project_img/portscanner/portscanner.png){: w="600",h="600"}

> If anything should be modified in the script please let me know.
{: .prompt-info }

You can find complete source code of Port Scanner here : [https://github.com/TheMj0ln1r/Port_Scanner](https://github.com/TheMj0ln1r/Port_Scanner)

# PythonZipCracker

This is a multiway password protected zip file cracker. The script is developed using python which can perform following tasks.

1. It can crack the password of a zip file with the rockyou.txt
2. It can crack the password of a zip file using your own password list
3. It can crack the password of a zip file with the bruteforcing of digits

Let's explore the main()


```python

def main():
	zfile = input("Enter absolute path of the zip file : ")
	if not os.path.isfile(zfile):
		print(zfile," is not found..")
		exit()
	dir = zfile[0:len(zfile)-4]
	if os.path.isdir(dir):
		print(dir, "is already present.. extracting may leads to overwrite of old files.")
		exit()
	print("""
Select method 
	1. Crack using built-in wordlist
	2. Crack with custom wordlist
	3. Crack using bruteforce method
	0. Exit
		""")
	choice = int(input("Enter your choice[1/2/3/0] : "))
	if choice == 1 :
		rocku(zfile)
	elif choice == 2 :
		wfile = input("Enter the absolute path of your password list: ")
		if not os.path.isfile(wfile):
			print(wfile," is not found..")
			exit()
		custom_passwd(zfile,wfile)
	elif choice == 3 :
		print("""
----------------------------------------------------------------------------
Bruteforcing method takes too much of time and system resources to perform..
Use this method to crack the passwords of length upto 4 only.
And the passwords are combination of digits only.
----------------------------------------------------------------------------
			""")
		passlen = int(input("Enter the length of password[Note: <5] : "))
		bruteforce(zfile,passlen)
	else :
		exit()
```
The main() function is printing the menu of the script and performing the input files are validations.
If the user chooses built-in wordlist method to crack the zip file then the `rocku()` function will be invoked.
```python
def rocku(zfile):
	wordlist = open("rockyou.txt","r")
	with pyzipper.AESZipFile(zfile) as zf:
		for i in wordlist:
			pwd = bytes(i.strip(),"utf-8")
			print("[-] Checking password : ",i)
			try:
				zf.extractall(pwd = pwd)
				print(50*"*")
				print("[+] Password is found : ",i)
				print("Files in ",zfile)
				for f in zf.namelist():
					print("\t",f)
				print(50*"*")
				break
		
			except:
				continue
```
The rocku() function is opening the rockyou.txt file in read mode and the zip file is opened using the pyzipper module. Then it is iterating over the each password in the rockyou.txt file and converting it into bytes. The password bytes is given as arguement to the extractall() function. If the password is found then the files will be extracted and the list of files and the password will be printed on screen. 

If the user chooses custom wordlist method to crack zip file the `custom_password()` function will be invoked.

```python
def custom_passwd(zfile,wfile):
	wordlist = open(wfile,"r")
	with pyzipper.AESZipFile(zfile) as zf:
		for i in wordlist:
			pwd = bytes(i.strip(),"utf-8")
			print("[-] Checking password : ",i)
			try:
				zf.extractall(pwd = pwd)
				print(50*"*")
				print("[+] Password is found : ",i)
				print("Files in ",zfile)
				for f in zf.namelist():
					print("\t",f)
				print(50*"*")
				break
		
			except:
				continue

```
The custom_password() function is doing the same thing as the rocku() function. Along with the zipfile the custom wordlist is needed to proceed.

If the user chooses bruteforce method the `bruteforce()` method will be invoked.
```python
def bruteforce(zfile,passlen):

	with pyzipper.AESZipFile(zfile) as zf:
		total_passwords = int(passlen* "9")
		for i in range(total_passwords+1):
			pwd = bytes(str(i),"utf-8")
			print("[-] Checking password : ",i)
			try:
				zf.extractall(pwd = pwd)
				print(50*"*")
				print("[+] Password is found : ",i)
				print("Files in ",zfile)
				for f in zf.namelist():
					print("\t",f)
				print(50*"*")
				break
		
			except:
				continue

```
A brute force attack is a hacking method that uses trial and error to crack passwords, login credentials, and encryption keys. It is a simple yet reliable tactic for gaining unauthorized access to individual accounts and organizations’ systems and networks. The hacker tries multiple usernames and passwords, often using a computer to test a wide range of combinations, until they find the correct login information.
The brute force approach is inefficient. For real-time problems, algorithm analysis often goes above the O(N!) order of growth.

As it is very time consuming for the long passwords i recommend to use this method for the passwords upto the length of 6. And this passwords are the combination of digits only.

### Requirements

You require these additional modules 

1. pyzipper

These modules will be pre installed on every system, if not then install them with `pip3 or pip`

**You need to download rockyou.txt and paste it in PythonZipCracker folder**
>Rockyou.txt : [https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt](https://www.kaggle.com/datasets/wjburns/common-password-list-rockyoutxt)

### Installation

```text 
git clone https://github.com/TheMj0ln1r/PythonZipCracker.git
cd PythonZipCracker
python3 crack.py
```
### Preview

![Preview](/assets/img/project_img/zipcrack/pythonzipcrack.png){: w="600",h="600"}

> If anything should be modified in the script please let me know.

You can find complete source code of PythonZipCracker here : [https://github.com/TheMj0ln1r/PythonZipCracker](https://github.com/TheMj0ln1r/PythonZipCracker)

# SecureFiles

With this tool we can able to encrypt text files, images, video's, audio's and any other files. And the decryption option is also available to decrypt the files.
This tool should be installed in the both reciever's and sender's system. 

Okay, Let me show some code..

Look at the `main()`

```python
def main():
	print("""
File Encrypter and Decrypter Menu
---------------------------------------------
Copy and paste the file in the "files" directory...
		1. Encrypt Image files      
		2. Encrypt Text files		
		3. Encrypt Audio files		
		4. Encrypt Video files		
		5. Encrypt other files		
		6. Decrypt Image files		
		7. Decrypt Text files		
		8. Decrypt Audio files		
		9. Decrypt Video files		
		10. Decrypt other files		
		0. Exit						
---------------------------------------------
		""")
	choice = int(input("Choose your option[0/1-10] : "))
	
	if choice == 1:
		file = input("Enter image name : ")
		check_file(file)
		encrypt(file,1)
	elif choice == 2:
		file = input("Enter Text file name : ")
		check_file(file)
		encrypt(file,2)
	elif choice == 3:
		file = input("Enter Audio file name : ")
		check_file(file)
		encrypt(file,3)
	elif choice == 4:
		file = input("Enter Video file name : ")
		check_file(file)
		encrypt(file,4)
	elif choice == 5:
		file = input("Enter File name : ")
		check_file(file)
		encrypt(file,5)
	elif choice == 6:
		file = input("Enter Image name : ")
		check_file(file)
		decrypt(file,6)
	elif choice == 7:
		file = input("Enter Text file name : ")
		check_file(file)
		decrypt(file,7)
	elif choice == 8:
		file = input("Enter Audio file name : ")
		check_file(file)
		decrypt(file,8)
	elif choice == 9:
		file = input("Enter Video file name : ")
		check_file(file)
		decrypt(file,9)
	elif choice == 10:
		file = input("Enter File name : ")
		check_file(file)
		decrypt(file,10)
	elif choice == 0:
		print("Terminating..")
		exit(1)
	else:
		print("Invalid choice..")
		exit(1)
```
The main() is displaying the menu of the tool and calling the functions based on the users choice.The check_file() function is checking wheather the file
is existed in the files directory or not.

Lets look at the image encryption case. The encrypt funtion is doing the encryption of the image.

```python
def encrypt(source_file,choice):
	file = open("./files/"+source_file,"rb")
	data = file.read()
	b_array = bytearray(data)
	key = input("Enter Key to encrypt {}: ".format(menu[choice]))
	random.seed("CH4R4NU"+key)
	for i in range(len(b_array)):
		k = random.getrandbits(8)
		b_array[i] = b_array[i] ^ k
	file.close()
	b64_array = base64.b64encode(b_array)
	if "." in source_file:
		ext = "."+source_file.split(".")[-1]
		file = open("./files/"+source_file.strip(ext)+"_encrypted"+ext,"wb")
	else:
		file = open("./files/"+source_file+"_encrypted","wb")
	file.write(b64_array)
	print("\tThe {} is encrypted and saved in files directory..".format(menu[choice]))
```
The encryption is done with the xor operation. The random.seed and base64 encoding is used to make the encryption stronger. The user can input his/her password called key as while encrypting the file. The key is the only way to decrypt the encrypted file.

If we encrypted our image successfully, the encrypted image will be saved at files folder. We can share this encrypted file to anyone but no one can view the actual image. To get the actual image we have to decrypt the image by specifiying the key which is used for encryption. The decryption process is done by the 
`decrypt` function.

```python
def decrypt(source_file,choice):
	file = open("./files/"+source_file,"rb")
	data = file.read()
	b_array = bytearray(base64.b64decode(data))
	key = input("Enter Key to decrypt image : ")
	random.seed("CH4R4NU"+key)
	for i in range(len(b_array)):
		k = random.getrandbits(8)
		b_array[i] = b_array[i] ^ k 
	file.close()
	if "." in source_file:
		ext = "."+source_file.split(".")[-1]
		source_file = "./files/"+source_file.strip(ext)+"_decrypted"+ext
		file = open(source_file,"wb")
	else:
		source_file = "./files/"+source_file+"_decrypted"
		file = open(source_file,"wb")
	file.write(b_array)
	isdecrypted(source_file,choice)
```
The bytes of the encrypted image file is decoded first from the base64, then the function asking the key and setting up the same random seed which is used in the encryption. Then the xor operation is performed, the bytes are written into a file and saved it in files folder. At the end of the decrypt function the
 `isdecrypted()` is called.
 ```python
def isdecrypted(file,choice):
	print("-"*50)
	typ = magic.from_file(file,mime=True)
	if ("text" in typ) and choice == 7:
		print("Text File is decrypted and saved in files directory..:-)")
	elif ("image" in typ) and choice == 6:
		print("Image is decrypted and saved in files directory..:-)")
	elif ("audio" in typ) and choice == 8:
		print("Audio file is decrypted and saved in files directory..:-)")
	elif ("video" in typ) and choice == 9:
		print("Video is decrypted and saved in files directory..:-)")
	elif ("text/plain" in typ ) and choice == 10:
		print("File is decrypted and saved in files directory..:-)")
	else:
		print("The key is wrong...")
		exit(1)
	print("-"*50)

```
The isdecrypted function is checking wheather the decrypted image is valid or not. The magical numbers of the image is being tested by the magic module.
If the magical numbers are matched the function is going to tell that the decryption is successfull, if not the function will tell that the key is wrong to decrypt. If the key is wrong the program is going to be exited.


### Requirements

You require these additional modules 

1. base64
2. magic
3. os
4. random

These modules will be pre installed on every system, if not then install them with `pip3 or pip`

>You need to copy your file and paste it in files folder of present in the SecureFiles folder to encrypt or decrypt the file
{: .prompt-info}

### Installation

```text 
git clone https://github.com/TheMj0ln1r/SecureFiles.git
cd SecureFiles
python3 SecureFiles.py
```
### Preview

![Preview](/assets/img/project_img/securefiles/securefiles.png){: w="600",h="600"}

> If anything should be modified in the script please let me know.

You can find complete source code of SecureFiles here : [https://github.com/TheMj0ln1r/SecureFiles](https://github.com/TheMj0ln1r/SecureFiles)

