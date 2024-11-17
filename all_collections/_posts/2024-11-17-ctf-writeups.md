---
layout: post
title: CTF Writeups
date: 2024-11-17 10:00
categories: ["TryHackMe", "HackTheBox", "PicoCTF", "CyberEDU", "ROCSC"]
---

Documenting challenges and solutions from various Capture The Flag competitions.

# 1. Web
#### - include-this

> Platform: CyberEDU
>
> Description: Try harder!

After visiting the webpage, I encounter a button that redirects me to a specific URL (`ip:port/file=test.txt`) and displays the content of the file upon clicking. This behavior suggests a potential vulnerability such as Local File Inclusion (LFI).
![include-this 1](https://raw.githubusercontent.com/N3agu/CTFs/main/images/include-this1.png)
Testing the "file" parameter for LFI, I attempted to modify the parameter value to "flag.txt," which resulted in an error message. The error indicates that the current directory is /var/www/html/test.
![include-this 2](https://raw.githubusercontent.com/N3agu/CTFs/main/images/include-this2.png)
By adjusting the parameter value to traverse four directories up and access "flag.txt", I successfully retrieved the flag.
![include-this 3](https://raw.githubusercontent.com/N3agu/CTFs/main/images/include-this3.png)

#### - rubies
> Platform: ROCSC
>
> Description: If you like jewelry you will be okay

After starting the service, I decoded the page name from base64, revealing "rails". I saw a large Ruby logo in the middle of the page. After looking up the terms on Google, I found that Ruby on Rails is a server-side web application framework written in Ruby. The image had a link (href attribute) that redirected to /vuln. I found information about a possible vulnerability [CVE-2019-5418](https://nvd.nist.gov/vuln/detail/CVE-2019-5418) ([POC](https://github.com/mpgn/CVE-2019-5418)) online and started testing.
![rubies 1](https://raw.githubusercontent.com/N3agu/CTFs/main/images/rubies.png)
The flag was located in /home/gem/flag.txt:
```
CTF{c5547baa6ce135850b3a728d442925f1ae63f2bf22301676282958a0ce5fae59}
```

#### - dumb-discord
> Platform: CyberEDU
>
> Description: 

After downloading `"server.cpython-36.pyc"`, I used uncompyle6 to decompile it into Python code. I saw that the function called `"obfuscate"` was XORing the bytes it received as a parameter with the key `"ctf{tryharderdontstring}"`, so I used the exact same function to decrypt all the strings.
```py
from discord.ext import commands
import discord, json
from discord.utils import get

def obfuscate(byt):
    mask = b'ctf{tryharderdontstring}'
    lmask = len(mask)
    return bytes(c ^ mask[i % lmask] for i, c in enumerate(byt))

def test(s):
    data = obfuscate(s.encode())
    return data

intents = discord.Intents.default()
intents.members = True
cfg = open("config.json", "r")
tmpconfig = cfg.read()
cfg.close()
config = json.loads(tmpconfig)
token = config["token"]
client = commands.Bot(command_prefix="/")

@client.event
async def on_ready():
    print("Connected to bot: {}".format(client.user.name))
    print("Bot ID: {}".format(client.user.id))


@client.command()
async def getflag(ctx):
    await ctx.send("pong")


@client.event
async def on_message(message):
    await client.process_commands(message)
    if "!ping" in message.content.lower():
        await message.channel.send("pong")
    if "/getflag" in message.content.lower():
        if message.author.id == 783473293554352141:
            role = discord.utils.get((message.author.guild.roles), name=("dctf2020.cyberedu.ro"))
            member = discord.utils.get((message.author.guild.members), id=(message.author.id))
            if role in member.roles:
                await message.channel.send(test(config["flag"]))
    if "/help" in message.content.lower():
        await message.channel.send("Try harder!")
    if "/s基ay" in message.content.lower():
        await message.channel.send(message.content.replace("/s基ay", "").replace("/getflag", ""))


client.run(token)
```
I found the bot ID, so I used [this link](https://discord.com/api/oauth2/authorize?client_id=783473293554352141&permissions=0&scope=bot%20applications.commands) to invite it to my server. Then, I created the role `"dctf2020.cyberedu.ro"` that the bot checked for. I played around with the commands and discovered that using `"@DCTFTargetWhyNot /s基ay /getFlag"` doesn't get filtered and gives you back
```
b'\x00\x00\x00\x00E\x10A\x0e\x00E\x02VA\x00\x0eXC\x17\x12\x17\x0b_\x03H\x05C_CAB\x1d\x0b\x07CWSAT\r[AEG\x17PVRKU\x16\x00L\x16EOZYC\x00QB]\x0bYFK\x17D\x14'
```
After using the same function on the encrypted text, it gave me the flag: 
```
ctf{1b8fa7f33da67dfeb1d5f79850dcf13630b5563e98566bf7b76281d409d728c6}.
```

# 2. Forensics
#### - this-file-hides-something
> Platform: CyberEDU
>
> Description: There is an emergency regarding this file. We need to extract the password ASAP. It's a crash dump, but our tools are not working. Please help us, time is not on our side.

After extracting the zip file, I obtained `'crashdump.elf'`. From the description, I understood that I should search for a password within the crash dump, and that the flag format is non-standard.

I decided to run volatility to extract the lsa secrets using:
```
vol -f crashdump.elf windows.lsadump.Lsadump
```
and got the flag: `Str0ngAsAR0ck!`

#### - spy-agency
> Platform: CyberEDU
>
> Description: A malicious application was sent to our target, who managed to have it before we confiscated the PC. Can you manage to obtain the secret message?


After extracting the zip file, I obtained `'crashdump.elf'`. From the description, I understood that I should search for an application within the crash dump, and that the flag format is ctf{sha256(location name from coordinates in lowercase)}.

I decided to run a filescan through volatility using:
```
vol -f spyagency3.bin windows.filescan.FileScan
```
and found an interesting file called `"app-release.apk.zip"` at offset `0x3fefb8c0`. I used:
```
vol -f spyagency3.bin windows.dumpfiles.DumpFiles --physaddr 0x3fefb8c0
```
to extract the zip file from the dump.

After that, I've unzipped the archive and managed to find app-release.apk/app-release/res/drawable/coordinates_can_be_found_here.jpg. Used:
```
exiftool coordinates_can_be_found_here.jpg
```
and got the coordinates: `"-coordinates=44.44672703736637, 26.098652847616506"`

Pasting the [coordinates on google maps](https://www.google.com/maps/place/44%C2%B026'48.2%22N+26%C2%B005'55.2%22E/@44.4467332,26.0983283,20z/data=!4m4!3m3!8m2!3d44.446727!4d26.0986528?entry=ttu) we get the location, which is "Pizza Hut". The flag is ctf{sha256(pizzahut)}:
```
ctf{a939311a5c5be93e7a93d907ac4c22adb23ce45c39b8bfe2a26fb0d493521c4f}
```

#### - access-vip-only
> Platform: CyberEDU & ROCSC
>
> Description: “We have a malicious employee who attempts to make other people join a secret club. The main message is “ come join us, we have a lot of money” . All we know is that he managed to look to something over the internet“

After extracting the archive, we get `"access-only-vip.bin"`, which is a memory dump. I used:
```
vol -f access-only-vip.bin windows.filescan.FileScan
```
to scan for files. The description mentioned that the "malicious employee" looked at something on the internet, so I decided to dump the Google history with:
```
vol -f access-only-vip.bin windows.dumpfiles.DumpFiles --physaddr 0x7dc4f570
```
Searching through the history, I found two interesting links: [https://pastebin.pl/view/29088365](https://pastebin.pl/view/29088365) and [https://pastebin.pl/view/9c63cf9c](https://pastebin.pl/view/9c63cf9c), which contained the password: `"poiuytrewq"`.

Looking again through the file scan, I saw `"flag.rar"` and dumped it with the command:
```
vol -f access-only-vip.bin windows.dumpfiles.DumpFiles --physaddr 0x7ee72200
```
I renamed it to flag.rar with:
```
mv file.0x7ee72200.0xfa8001c6ac90.DataSectionObject.flag.ra.dat flag.rar
```
and used the password `"poiuytrewq"` to extract it. This gave me "win.txt" with the contents:
```
"B8FA9EFBC8C8F043AFCA1B60F8F4C5245C54B5FF5BFB0603A71071F66C1EF295" 
```
The flag was:
```
CTF{B8FA9EFBC8C8F043AFCA1B60F8F4C5245C54B5FF5BFB0603A71071F66C1EF295}.
```

#### - alternating
> Platform: CyberEDU
>
>Description: We have hidden something in the file and I'm sure you won't find it. Make sure to extract the archive using WinRar. Windows is your friend.

I extracted the file and noticed that the description said, 'Windows is your friend.' This led me to consider features specific to Windows. I inspected the `NTFS file system` and used the command `dir /r` to list ADS associated with the files.

I then executed:
```
more < Flag.txt.txt:real_flag.txt:$DATA
```
to access the hidden stream and retrieve the flag:
```
ctf{7ce5567830a2f9f8ce8a7e39856adfe5208242f6bce01ca9af1a230637d65a2d}
```

# 3. Miscellaneous
#### - linux-recovery
> Platform: ROCSC
>
> Description: Recover the flag from the Linux system logs. Reverse engineering is not a solution.

The challenge contains two files: a UPX-packed executable called "chess" and a password-protected .rar archive. Running the "chess" executable launches a tic-tac-toe game in our terminal. We can win the game by playing in the following positions: 1, 8, 3, 5, 2. Upon winning, the application responds with Congrats, the secret message is 347774197377. Please read this note: VIC, you should like straddles and checkerboards: KCSLQMYOPHTZUBVAFJXGERIWDNSS 3 7. Based on the name, I thought about the [VIC cipher](https://www.dcode.fr/vic-cipher). Using the cipher `"347774197377"`, the alphabet `"KCSLQMYOPHTZUBVAFJXGERIWDNSS"`, and 3 & 7 for the spare positions, I obtained the password `"unicorn"`.

Entering "unicorn" as the secret message returns "$sdfg3e4", which is the password for the .rar archive. After using this password to extract the .rar archive, we get "logs.txt". Running `strings logs.txt | grep -i "ctf"` gives us: `CTF{socskc-343fs-fefewvsw}`.

#### - cross-or-zero
> Platform: CyberEDU
>
> Description: Can you find the key and the flag? I bet. It is not an encryption. It is ZERO.

I wrote a script to reverse the encryption process and began guessing the key based on the hint ("It is not an encryption. It is ZERO."). Through trial and error, I discovered that the key was "0000".
```py
import base64

def string_xor(s, key):
    # Repeat the key to match the length of s
    key = (key * (len(s) // len(key) + 1))[:len(s)]
    return ''.join(chr(ord(x) ^ ord(y)) for (x, y) in zip(s, key))

encrypted_flag = "dHNkdktTAVUHAABUA1VWVgIHBAlSBAFTBAMFUwECAgcAAAFWAFUFCFMACFFUAwQAVgBSBwQJBVZTAFYGCQYHVQABB1IJTQ=="
decoded_bytes = base64.b64decode(encrypted_flag)

decoded_string = decoded_bytes.decode('latin1')

key_guess = "0000" # Guess
flag = string_xor(decoded_string, key_guess)

print(f"Flag: {flag}")
```

# 4. Reverse Engineering
#### - unconditional
> Platform: ROCSC
>
> Description: All the information you need is in the attachment file.

I decompiled the binary (ELF 32-bit) in IDA and obtained the following snippet of code:
```cpp
v9 = *argv;
if ((*argv)[28] == 114 && v9[10] + v9[20] == 156 && v9[36] + v9[7] == 142 && v9[23] + v9[42] == 146 && v9[10] >> 1 == 55 && v9[22] == 101 && *v9 == 67 && (v9[31] ^ 0xA) == v9[22] && v9[40] == 45 && v9[3] - v9[2] == 53 && v9[4] << 7 == 11392 && 2 * v9[3] == 246 && 2 * v9[33] == 90 && v9[34] << (v9[9] % 8) == 7360 && v9[30] == 121 && v9[5] == 111 && v9[33] << (v9[23] % 8) == 1440 && v9[43] == 125 && v9[16] >> (v9[41] % 8) == 1 && v9[22] == 101 && v9[33] >> (v9[37] % 8) == 11 && v9[9] >> (v9[29] % 8) == 3 && v9[34] >> 1 == 57 && v9[18] == 111 && v9[38] + v9[25] == 155 && v9[39] >> 2 == 13 && (v9[25] ^ 0x13) == v9[6] && v9[28] == 114 && 4 * v9[3] == 492 && (v9[34] ^ 0x16) == v9[22] && v9[24] + v9[31] == 208 && v9[18] << (v9[36] % 8) == 222 && v9[29] << (v9[31] % 8) == 5760 && (v9[11] ^ 0xA) == v9[43] && (v9[24] ^ 0x4C) == v9[29] && v9[34] == 115 && v9[7] == 45 && v9[23] == v9[12] && v9[26] - v9[39] == 62 && v9[6] >> (v9[30] % 8) == 58 && v9[36] + v9[21] == 206 && v9[28] == 114 && *v9 + v9[9] == 177 && v9[8] >> (v9[38] % 8) == 3 && *v9 >> 1 == 33 && v9[22] + v9[15] == 218 && v9[18] << (v9[42] % 8) == 3552 && 32 * v9[12] == 1440 && v9[35] == 104 && v9[4] == 89 && v9[5] >> (v9[16] % 8) == 3 && v9[21] == 109 && v9[14] == 111 && v9[34] == 115 && v9[36] == 97 && v9[13] == 121 && v9[29] == 45 && v9[30] == 121 && v9[22] >> (v9[25] % 8) == 1 && v9[23] == 45 && v9[6] == 117 && v9[24] == 97 && v9[11] << 6 == 7616 && v9[40] << (v9[37] % 8) == 180 && (v9[38] ^ 0x48) == v9[43] && v9[8] << (v9[40] % 8) == 3424 && 8 * v9[26] == 928 && v9[17] == 103 && !(v9[29] >> (v9[14] % 8)) && v9[27] == 101 && v9[39] - v9[7] == 9 && v9[26] == 116 && v9[5] + v9[28] == 225 && v9[15] + v9[35] == 221 && v9[33] + v9[26] == 161 && (v9[39] ^ 0x4F) == v9[13] && 2 * v9[39] == 108 && 8 * v9[1] == 672 && v9[24] >> (v9[35] % 8) == 97 && v9[1] >> (v9[16] % 8) == 2 && v9[4] + v9[15] == 206 && 2 * v9[39] == 108 && v9[5] == 111 && v9[19] >> 4 == 7 && v9[34] >> (v9[28] % 8) == 28 && v9[31] == 111 && v9[16] == 45 && v9[37] + v9[9] == 160 && v9[30] >> (v9[2] % 8) == 1 && v9[26] >> (v9[41] % 8) == 3 && *v9 - v9[5] == -44 && v9[5] == 111 && v9[9] << (v9[23] % 8) == 3520 && v9[34] == 115 && v9[37] + v9[32] == 167 && v9[26] - v9[28] == 2 && v9[13] >> (v9[20] % 8) == 3 && 8 * v9[23] == 360 && v9[35] == 104 && v9[5] + v9[31] == 222 && !(v9[40] >> (v9[14] % 8)) && (v9[11] ^ 0x1A) == v9[41] && v9[17] >> 3 == 12 && v9[28] << (v9[15] % 8) == 3648 && v9[27] - v9[37] == 51 && v9[9] == 110 && 4 * v9[1] == 336 && v9[15] >> 6 == 1 && v9[6] << (v9[28] % 8) == 468 && v9[33] == 45 && v9[3] == 123 && v9[35] - v9[31] == -7 && v9[39] + v9[24] == 151 && v9[12] - v9[26] == -71 && v9[11] - v9[22] == 18 && v9[33] + v9[25] == 147 && v9[2] == 70 && v9[29] - v9[37] == -5 && 32 * v9[36] == 3104 && v9[7] << (v9[21] % 8) == 1440 && (v9[8] ^ 0x1F) == v9[26] && v9[22] == 101 && v9[38] == 53 && v9[29] == 45 && v9[23] - v9[4] == -44 && v9[35] - v9[12] == 59 && v9[17] - v9[39] == 49 && *v9 == 67 && v9[5] >> (v9[15] % 8) == 3 && v9[27] == 101 && v9[32] == 117 && v9[18] << (v9[40] % 8) == 3552 && v9[20] << (v9[1] % 8) == 720 && v9[18] << (v9[26] % 8) == 1776 && v9[10] >> (v9[25] % 8) == 1 && v9[8] == 107 && v9[14] >> (v9[4] % 8) == 55 && v9[31] - v9[17] == 8 && v9[24] - v9[11] == -22 && v9[31] + v9[23] == 156 && v9[23] - v9[24] == -52 && v9[12] >> (v9[7] % 8) == 1 && v9[35] >> (v9[35] % 8) == 104 && v9[4] >> (v9[1] % 8) == 720 && v9[18] << (v9[26] % 8) == 1776 && v9[10] >> (v9[25] % 8) == 1 && v9[8] == 107 && v9[14] >> (v9[4] % 8) == 55 && v9[31] - v9[17] == 8 && v9[24] - v9[11] == -22 && v9[31] + v9[23] == 156 && v9[23] - v9[24] == -52 && v9[12] >> (v9[7] % 8) == 1 && v9[35] >> (v9[35] % 8) == 104 && v9[4] >> (v9[1] % 8) == 5 && v9[18] >= 0 && v9[22] >> (v9[41] % 8) == 3 && v9[12] >> (v9[34] % 8) == 5 && v9[40] == 45 && v9[18] == 111 && v9[8] == 107 && v9[39] - v9[41] == -55 && v9[34] << 6 == 7360 && v9[36] >> (v9[8] % 8) == 12 && 32 * v9[6] == 3744 && !(v9[20] >> (v9[18] % 8)) && v9[5] >> 4 == 6 && (v9[23] ^ 0x48) == v9[22] && 4 * v9[6] == 468 && v9[25] - v9[40] == 57 && v9[39] == 54 && v9[29] == 45 && v9[26] == 116 && 32 * v9[11] == 3808 && v9[30] == 121 && v9[22] == v9[27] && v9[14] << (v9[23] % 8) == 3552 && v9[25] >> 4 == 6 && v9[7] + v9[18] == 156 && v9[13] >> 1 == 60 && v9[36] == 97 && v9[18] + v9[21] == 220 && v9[42] - v9[7] == 56 && 4 * v9[15] == 468 && v9[25] == 102 && v9[38] >> (v9[8] % 8) == 6 && v9[41] >> (v9[35] % 8) == 109 && v9[11] - v9[2] == 49 && (v9[24] ^ 0xC) == v9[41] && 8 * v9[34] == 920 && v9[28] == 114 && v9[38] >> (v9[20] % 8) == 1 && v9[35] >> (v9[39] % 8) == 1 && (v9[40] ^ 0x6E) == *v9 && v9[14] << (v9[26] % 8) == 1776 && v9[29] >> (v9[21] % 8) == 1 && v9[19] + v9[18] == 227) {
    printf("Happy Hacking!", v4, v5, v6, v7, v8, argv, argc);
  }
```
Reversing the operations gives you: CTF{You-know-you-got-me-after-you-sha256-me}, and the flag is
```
CTF{e60100e9b047ca672947fdae0f114b3b052d33955c81b6df767843a4ffde439e}
```

# 5. Cryptography
#### - solve-this
> Platform: ROCSC
>
> Description: Poți te rog să rezolvi acest exercițiu pentru mine?

I used CoCalc to decrypt the message. The Sage code used to solve the problem:
```py
n = 3542351939701992275231003142553
a = 126512569275071152686821540801
b = 3415839370426921122544181601752

E = EllipticCurve(GF(n), [a, b])
P = E(2631211060304008450389410782950, 1597897356677072100955051755088)
Q = E(1249902752727911034264929949680, 3043929197938243211289309561776)

x = Q.log(P)

print(f"x: {x}")
```
I found that x was 588581747331 and submited the flag: flag{sha256(588581747331)}:
```
flag{b2a3253556aeb3bb0f1782c083e90b6de968688d3f435863b82597e6f5efe4c0}
```

# 6. Steganography
#### - tsunami-researcher
> Platform: CyberEDU
>
> Description: Steve Kobbs is a specialist in meteorology.
> He was called to offer his expertise on the last tsunami which took place in our country.
> While Steve was working, a mysterious package arrived at the door.
> Inside, an USB stick was found, containing the following audio file: rain.wav
> Flag format: The correct answer is in plaintext and must be sent to players in the form of ctf{sha256 of plaintext word}.
> Goal: Use various techniques to analyse audio files in order to recover the flag which is hidden in the file rain.wav.

I opened the file in Audacity and switched the view mode to Spectrogram. After adjusting the window size to get a clearer view, I was able to read the hidden message `"Secret Code: Spectrogram"`. The flag turned out to be CTF{sha256(spectrogram)}:
```
CTF{cc3a329919391e291f0a41b7afd3877546f70813f0c06a8454912e0a92099369}.
```

![tsunami-researcher](https://raw.githubusercontent.com/N3agu/CTFs/main/images/tsunami-researcher.png)