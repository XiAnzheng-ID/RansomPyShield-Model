# RansomPyShield-Model
Whats make this ML Model Different than some public and free model out there? this model integrate Yara, CAPA(WIP-Experimental), blint(WIP) for its indicator , not just static PE Information from lief/pefile/other

Why?? Some Malware can spoof , hide , encrypt , obfus most of their data making extracting them hard, some Model or even bad AV can be bypassed or be fooled using this way

With Yara, CAPA, blint help we can extract some other crucial data or indicator that the threat actor try to hide, thus this may help the ML to decide the file is Malicious or not

Not just that these tools can also help extract the data that taking much time to extract or even hard to do for some people

as a bonus this model also can detect some other random malware because how Ransomware file works almost the same with most Malware out there

so does it doest have weakness? good question , it does, some threat actor can bypass it using some fileless attack vector eg:CMD/Powershell attack, which we need different approach not Static Identification

# How to use?
* extract.py
```bash
extract.py --ransomware "C:\path\to\sample" --benign "C:\path\to\benign" --yara_rules "C:\path\to\yara_rules" --blint "C:\path\to\blint.exe"
```
capa and blint is an optional argumen if you dont wanna use em as em still (WIP) , but if you wanna make your own model feel free to use it as it is rn

* train.py
just run it as a normal script

* run.py (for running the model and test the 
accuracy)
```bash
run.py --folder "E:\Dataset\Random\Malware" --model "ransompyshield.pkl" --yara_rules "D:\Kuliah\Code\Skripsi\Rule --blint --label benign/ransomware
```

# Proof & Information
This model as tested against 64 random malware and 64 benign file and Trained with 800 real Ransomware Sample and Benign File

and i forgot to keep some dataset as testing so as of now , this model was tested against 16 real Ransomware Sample

Do remember that somefile were failed to be processed so it can be less (check the proof and dataset)

* Random Malware proof
<img src="https://github.com/XiAnzheng-ID/RansomPyShield-Model/blob/main/Proof/Accuray_Random_Malware.png" width="512" height="256">

* Random Benign proof
<img src="https://github.com/XiAnzheng-ID/RansomPyShield-Model/blob/main/Proof/Accuray_Random_Benign.png" width="512" height="256">

* Real Ransomware Sample Proof
<img src="https://github.com/XiAnzheng-ID/RansomPyShield-Model/blob/main/Proof/Accuracy_Ransomware_Sample.png" width="512" height="256">
