# How to set up and use



#### 1\. Install Python

Download and install Python 3.13 or higher from:

https://www.python.org/downloads/

Important: During installation, check the box “Add Python to PATH”.




#### 2\. Open Command Prompt or PowerShell

Press Win + R, type "cmd" or "powershell", press Enter.




#### 3\. Go to the project folder

Type:cd C:\\Phishmageddon\\analysis\_scripts

Press Enter.



#### 4\. Install needed Python packages

Run these commands:



pip install requests

pip install beautifulsoup4

pip install email-validator

pip install textblob

python -m textblob.download\_corpora

(you can directly copy and paste them all at once)





#### 5\. Put your email files (.eml) into "incoming\_emails" folder

Place all the emails you want to scan in this folder.



#### 

#### 6\. Run the tool

In terminal, run:

python phishmageddon.py

The tool will scan all email files in the "incoming\_emails" folder and save reports in the reports folder.





























