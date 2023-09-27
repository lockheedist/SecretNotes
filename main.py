from tkinter import *
from PIL import ImageTk, Image
from tkinter import messagebox
import base64

def clearstrings():
    keyentry.delete(0,END)
    titleentry.delete(0,END)
    textbox.delete("1.0",END)


skey=12
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt():
    title=titleentry.get()
    message=textbox.get("1.0","end-1c")
    master_secret=keyentry.get()
    if len(title) == 0 or len(message) == 0 or len(master_secret)==0:
        messagebox.showwarning("Input Error","Please provide correct inputs!")
    else:
        #encryptionlater
        with open("keys.txt","a") as datas:
            datas.write(f"\n{title}\n{encode(master_secret,message)}")
        clearstrings()

def decrypt():
    message = textbox.get("1.0", "end-1c")
    master_secret=keyentry.get()
    decrypted_message=decode(master_secret,message)
    clearstrings()
    #textbox.insert("1.0",decrypted_message)
    messagebox.showinfo("Decrypted Note",f"{decrypted_message}")



wn = Tk()
wn.title("Secret Notes @lockheedist")
wn.minsize(400,600)
wn.config(bg="white",)
#Image label
img = ImageTk.PhotoImage(Image.open("secsec.png"))
imagelabel= Label(image=img)
imagelabel.pack()

#title label and entry
titlelabel= Label(text="Enter your title")
titlelabel.pack()
titleentry= Entry()
titleentry.pack()

#textbox label and textbox
textboxlabel= Label(text="Write your Note")
textboxlabel.pack()
textbox= Text(width=40)
textbox.pack()

#keyentry label and entry
keylabel= Label(text="Enter Master Key")
keylabel.pack()
keyentry= Entry()
keyentry.pack()




#Save&Encrypt Button
saveenrcypt= Button(text="Save&Encrypt",command=save_and_encrypt)
saveenrcypt.config()
saveenrcypt.pack()


#Decrypt button
decrypt= Button(text="Decryption",command=decrypt)
decrypt.pack()








wn.mainloop()