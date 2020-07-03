echo "I need your name or username. Please tell me your name."
unset getUsername
while [[ ! ${getUsername} =~ ^[A-Za-z]{4,}$ ]]; do
    echo "Only username more than 4 letters and lowercase and/or uppercase without number"
    read getUsername
done
echo "Proceeding to generate public and private key."
openssl genrsa -out "private-${getUsername}.txt" 2048
chmod 444 "private-${getUsername}.txt"
openssl rsa -in "private-${getUsername}.txt" -outform PEM -pubout -out "public-${getUsername}.txt"
chmod 444 "public-${getUsername}.txt"
gcc decrypt.c pki.c -o decrypt -lcrypto -w
rm "/etc/pam.d/babylon/enc-${getUsername}.txt"
./decrypt ${getUsername}
mv "private-${getUsername}.txt" /etc/pam.d/babylon
echo "Setup done! You can now move the generated \"public-[YOUR CREDENTIAL].txt\" into your flash drive."
# echo "Check your device list."
# unset usbName
# isDirExist=0
# while [[ isDirExist=0 ]]; do
#     echo "Please enter your device name : "
#     read usbName
#     echo "/media/${USER}/${usbName}/"
#     if [ -d "/media/${USER}/${usbName}/" ]; then
#         isDirExist=1
#     fi
# done
# mv "public-${getUsername}.txt" "/media/${USER}/${usbName}/"