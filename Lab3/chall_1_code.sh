{\rtf1\ansi\ansicpg1252\cocoartf2822
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\paperw11900\paperh16840\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 # 24b3983\
# The name of the 3 files have not been changed \
# I saved the given 3 files in the folder and location mentioned below \
\
cd "/Users/hrishikeshbingewar/Downloads/vscode/EE325/Asgnt2/LAB3/q1"\
\
\
$key_data = (gc key.hex -Raw).Trim()\
$initialization_vector = (gc iv.hex -Raw).Trim() \
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0
\cf0 # Reading and cleaning the cryptographic inputs\
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0
\cf0 \
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0
\cf0 \
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0
\cf0 "=== MAC 1: HMAC-SHA256 ===" | Write-Host\
openssl mac -in message.txt -digest sha256 -macopt key:$key_data\
#First MAC:HMAC-SHA256\
\
\
"`n=== MAC 2: CMAC-AES-128-CBC ===" | Write-Host\
openssl mac -in message.txt -cipher aes-128-cbc -macopt key:$key_data\
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0
\cf0  #second MAC: CMAC-AES-128-CBC\
\
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0
\cf0 \
"`n=== MAC 3: GMAC-AES-128-GCM ===" | Write-Host\
openssl mac -in message.txt -cipher aes-128-gcm -macopt key:$key_data -macopt iv:$initialization_vector\
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0
\cf0 #third MAC: GMAC-AES-128-GCM}